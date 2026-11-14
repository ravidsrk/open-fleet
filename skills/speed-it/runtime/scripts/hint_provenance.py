#!/usr/bin/env python3
"""Provenance and currency for episodic memory hints (#605).

``search_sessions.py --episodic-hint`` retrieves prior run manifests and session hits for the
paths a task is about to touch. Fencing that text (guard_text) answers "can it forge structure?";
it never answered "is it still true HERE?". A finding goes stale after a rename, a fix, a branch
change, a changed test or dependency, or a rewritten artifact, while its text stays perfectly
clean. This module answers the second question, read-only, against the LIVE source:

* **Provenance.** Every hint names its source repo/revision (or ``unknown``), the artifact it was
  drawn from with that artifact's sha256, the path/symbol scope it was checked against, the
  producing run, and why it matched (field, candidate, query, match kind).
* **Currency.** ``CURRENT`` only when every check passed: the source revision is in the live repo
  and an ancestor of the live revision; no scoped path changed, was deleted or renamed since; no
  related test changed; the recorded artifact bytes still match; no newer record and no current
  observation contradicts it. ``STALE`` and ``SUPERSEDED`` are suppressed from a worker-facing
  (current-mode) hint; ``UNKNOWN`` is shown, labelled, and never upgraded -- absent provenance and
  changed dependencies mean unknown, not fresh.
* **Labels are computed, never read.** A manifest saying ``"currency": "CURRENT"`` or ``"status":
  "fresh"`` changes nothing: the label comes from git and the artifact bytes alone.
* **CURRENT is narrow.** It means "nothing in the checked scope changed since the source
  revision". It is not "true", it is never completion evidence (evidence-manifest.md: only a new
  independent verification is), and it never outranks the frozen task or the live source.

Memory stays advisory data: nothing here writes a file, and every git call is a read-only
subcommand (``git()`` refuses anything else) with optional locks off, so building a hint cannot
edit agent instructions, permissions, the live checkout or the run archive -- and a ``diff`` or
``log`` runs in git custody, against a git dir whose config defines no filter or diff driver, so
reading it runs nothing its owner named, even one added while it reads (#629, W4 custody sweep).

Library only: no CLI, no exit codes.
"""
import ast
import datetime
import errno
import fnmatch
import functools
import hashlib
import os
import re
import stat
import subprocess
import warnings
from pathlib import Path

import diff_scope
import gitexec

CURRENT, UNKNOWN, SUPERSEDED, STALE = "CURRENT", "UNKNOWN", "SUPERSEDED", "STALE"
# Severity order: the worst reason a record carries is its label.
SEVERITY = {CURRENT: 0, UNKNOWN: 1, SUPERSEDED: 2, STALE: 3}
SUPPRESSED = frozenset({STALE, SUPERSEDED})

# The ONLY git subcommands a hint may run. diff/ls-files run with GIT_OPTIONAL_LOCKS=0 so not even
# the index stat cache is refreshed: retrieval leaves every byte of both repositories alone.
READ_ONLY_GIT = frozenset({"rev-parse", "cat-file", "merge-base", "diff", "ls-files", "log"})
# The read-only subcommands that can render content through an attribute-selected driver.
CONTENT_GIT = frozenset({"diff", "log"})
# The ones that run in git custody: those, and ls-files, which reads the ignore files (the
# repository's core.excludesFile is carried as data there, and no user default is opened).
CUSTODY_GIT = CONTENT_GIT | {"ls-files"}

REV = re.compile(r"^[0-9a-f]{7,64}$")
GLOB_CHARS = set("*?[")
# One definition of a test path: the same rule the scope gate and the verifier use (diff_scope.py).
TEST_PATH = next(rx for name, rx in diff_scope.PATH_RULES if name == "TESTS")
# Dependency manifests and lockfiles: a change to any of them leaves a historical verdict's
# currency UNKNOWN even when the scoped source is byte-identical (MemTrace's test/dependency case).
DEPENDENCY_FILES = frozenset({
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
    "npm-shrinkwrap.json", "requirements.txt", "requirements-dev.txt", "constraints.txt",
    "pyproject.toml", "uv.lock", "poetry.lock", "pipfile", "pipfile.lock", "setup.py", "setup.cfg",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "composer.json",
    "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "mix.exs", "mix.lock", "package.swift", "package.resolved", ".mise.toml", "mise.toml",
    ".tool-versions", ".python-version", ".nvmrc", ".node-version",
})
PASS_STATUSES = frozenset({"verified", "merged", "pass", "passed", "green", "done", "fixed",
                           "closed", "resolved", "shipped"})
FAIL_STATUSES = frozenset({"parked", "failed", "fail", "red", "regressed", "suspect", "blocked",
                           "wedged", "flaky", "open", "refuted"})
MATCH_KINDS = ("exact", "query-glob", "dir", "basename", "record-glob")
STRUCTURED_FIELDS = ("files_touched", "scope_allow", "oracle_scope")
SYMBOL_SPLIT = re.compile(r"::|#")
# Python source is bounded by its own parser (PR #639 review: the indentation walk misread
# decorators, then tabs, then a column-zero line inside a multiline string -- each cut a definition
# short, so a changed body stayed CURRENT). The walk below remains for other languages only.
PYTHON_SUFFIXES = (".py", ".pyi", ".pyw")
DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
AMBIGUOUS = object()  # a name defined more than once at its shallowest depth: no single block
DEF_LINE = r"^(?P<indent>[ \t]*)(?:export\s+)?(?:async\s+)?(?:def|class|function|func|fn)\s+{sym}\b"


class ProvenanceError(Exception):
    """The live source cannot be read (not a repository, unknown revision, git absent, a file
    that cannot be opened)."""


def git(repo, *args, text=True):
    """Run one READ-ONLY git subcommand in ``repo``. Anything else is refused, not attempted.

    ``diff``, ``log`` and ``ls-files`` run in git custody (gitexec.custody, W4 custody sweep;
    ``ls-files`` because it reads the ignore files, the repository's core.excludesFile carried as
    data and no user default opened): against a git dir
    this module builds over the checkout's objects and index, whose config declares no filter,
    textconv, diff or merge driver, with the checkout's own work tree. A working-tree diff runs a
    clean filter, and patch output a textconv or diff command, that a ``.gitattributes`` or
    ``$GIT_DIR/info/attributes`` line selects -- a command the worker who owns the checkout named.
    Blanking the drivers its config declares (gitexec.driver_blanks, #629) left a window: one added
    after the listing ran. In custody a selected driver is undefined, whenever it was added. The
    listing stays as a belt and keeps its contract: a config that cannot be read is a
    ProvenanceError, never a diff run with nothing blanked; so is a checkout the custody refuses
    (a partial clone, say). The other subcommands never read content through attributes, so they
    run in ``repo`` itself; a ``rev-parse`` probe of a path that is not a repository still comes
    back as a failed process, not an exception. Every call runs under gitexec.custody_env: no lazy
    fetch, no transport but ``file``, no signature-verifying child, no inherited
    repository selector; a ``diff`` never probes a checked-out submodule with a child git (which
    would run under the submodule's own config)."""
    if not args or args[0] not in READ_ONLY_GIT:
        raise ProvenanceError(f"refused git {args[0] if args else '(none)'}: hints are read-only")
    try:
        gitexec.refuse_blocking_files(repo)  # a config, include or `shallow` git would block opening
    except OSError as exc:
        raise ProvenanceError(f"git would block reading {repo}: {exc}") from exc
    if args[0] not in CUSTODY_GIT:
        return _run_git(["-C", str(repo)], args, (), text)
    try:
        blanks = gitexec.driver_blanks(repo)
    except gitexec.DriverQueryFailed as exc:
        raise ProvenanceError(f"cannot neutralise {repo}'s filter and diff drivers: {exc}") from exc
    if args[0] == "diff":
        # Never a child git inside a checked-out submodule, which would run under the submodule's
        # own config; a moved gitlink still shows (gitexec.NO_SUBMODULE_CHILD).
        args = ("diff", gitexec.NO_SUBMODULE_CHILD, *args[1:])
    try:
        with gitexec.custody(repo) as custody:
            return _run_git(custody.lead, args, [*custody.pairs, *blanks], text)
    except gitexec.GitCustodyRefused as exc:
        raise ProvenanceError(f"cannot read {repo} in git custody: {exc}") from exc
    except subprocess.SubprocessError as exc:
        # A git the custody's own setup ran (rev-parse, config) that timed out: unknown, never a
        # raw TimeoutExpired (Codex on PR #724, round 6).
        raise ProvenanceError(f"cannot set up git custody for {repo}: {exc}") from exc


def _run_git(lead, args, pairs, text):
    env = gitexec.custody_env(blanks=pairs)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        return subprocess.run(gitexec.argv(*lead, *args), env=env, capture_output=True,
                              text=text, timeout=60, check=False, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        # A git that blocked (a FIFO in the work tree) until its timeout: unknown, never a crash
        # (PR #724 re-attack).
        raise ProvenanceError(f"git {args[0]} timed out after {exc.timeout}s") from exc


def _ok(proc):
    return proc.returncode == 0


def normalize_path(value):
    text = str(value or "").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def split_symbol(token):
    """``src/a.py::refresh`` / ``src/a.py#refresh`` -> (``src/a.py``, ``refresh``)."""
    parts = SYMBOL_SPLIT.split(normalize_path(token), maxsplit=1)
    path = parts[0]
    symbol = parts[1].strip() if len(parts) > 1 and re.fullmatch(r"[A-Za-z_][\w.]*", parts[1].strip()) else None
    return path, symbol


def is_glob(path):
    return any(ch in GLOB_CHARS for ch in path)


def match_kind(candidate, query):
    """How a record's path token matches a query path, or None. Accepts exactly the pairs
    search_sessions._path_matches accepts, and names WHICH rule matched (the selection reason)."""
    c, t = normalize_path(candidate), normalize_path(query)
    if not c or not t:
        return None
    if c == t:
        return "exact"
    if fnmatch.fnmatchcase(c, t):
        return "query-glob"
    if fnmatch.fnmatchcase(t, c):
        return "record-glob"
    if c.startswith(t.rstrip("/") + "/") or t.startswith(c.rstrip("/") + "/"):
        return "dir"
    if "/" not in c or "/" not in t:
        cb, tb = os.path.basename(c), os.path.basename(t)
        if cb and tb and "*" not in tb and "?" not in tb and cb == tb:
            return "basename"
    return None


def checked_path(candidate, query, kind):
    """The concrete path whose content decides currency for one match, or None when both
    sides are patterns (the scope cannot be resolved to bytes)."""
    c, t = normalize_path(candidate), normalize_path(query)
    concrete = [p for p in (c, t) if p and not is_glob(p)]
    if kind == "exact":
        return c
    if kind == "query-glob":
        return c if not is_glob(c) else None
    if kind == "record-glob":
        return t if not is_glob(t) else None
    if kind == "basename":
        with_dir = [p for p in concrete if "/" in p]
        return with_dir[0] if with_dir else (concrete[0] if concrete else None)
    if kind == "dir":
        return max(concrete, key=len).rstrip("/") if concrete else None
    return None


def outcome(status):
    """A record's claimed outcome class: pass / fail / None (no outcome claimed)."""
    word = str(status or "").strip().lower()
    if word in PASS_STATUSES:
        return "pass"
    if word in FAIL_STATUSES:
        return "fail"
    return None


# What a hint reads from disk, in the process that builds it (the scan's child has exited by then).
# A manifest re-read or a live file is held whole to be compared, so it is read only up to
# MAX_READ_BYTES (search_sessions' MAX_FILE_BYTES: a manifest the scan accepted is no larger); an
# evidence file is hashed as it streams, up to MAX_HASH_BYTES. Each is opened without following a
# final link and without blocking, and must be a regular file by its descriptor: Path.read_bytes()
# followed a link swapped in since the check (to /dev/zero: read without end), blocked on a FIFO,
# and held a file of any size whole (W5-21 class, re-attack of 2d254d0f).
MAX_READ_BYTES = 64 << 20
MAX_HASH_BYTES = 1 << 30
_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_CLOEXEC", 0))


class ArtifactRefused(OSError):
    """A file a hint will not read: ``kind`` is ``irregular`` (a link, FIFO, device or socket) or
    ``oversized`` (past the bound it is read under). The hint says so in its reasons."""

    def __init__(self, kind, path):
        super().__init__(f"{path}: {kind}")
        self.kind = kind


def _open_regular(path, limit):
    """A descriptor on the regular file at ``path`` of at most ``limit`` bytes, or ArtifactRefused."""
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise ArtifactRefused("irregular", path) from None
        raise
    st = os.fstat(fd)
    kind = "irregular" if not stat.S_ISREG(st.st_mode) else "oversized" if st.st_size > limit else None
    if kind is not None:
        os.close(fd)
        raise ArtifactRefused(kind, path)
    return fd


def _chunks(path, limit):
    """The bytes of ``path`` in chunks, never more than ``limit`` (a file grown past it while read
    is ``oversized``)."""
    fd = _open_regular(path, limit)
    try:
        read = 0
        while chunk := os.read(fd, min(1 << 20, limit + 1 - read)):
            read += len(chunk)
            if read > limit:
                raise ArtifactRefused("oversized", path)
            yield chunk
    finally:
        os.close(fd)


def read_regular(path, limit=MAX_READ_BYTES):
    """The bytes of the regular file at ``path``, at most ``limit``; ArtifactRefused otherwise."""
    return b"".join(_chunks(path, limit))


def sha256_file(path, limit=MAX_HASH_BYTES):
    """The sha256 of the regular file at ``path``, streamed, at most ``limit`` bytes read;
    ArtifactRefused otherwise."""
    digest = hashlib.sha256()
    for chunk in _chunks(path, limit):
        digest.update(chunk)
    return digest.hexdigest()


def _epoch(stamp):
    try:
        parsed = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def recorded_time(manifest, unit, run_id):
    """When the record CLAIMS it was made (newest command ts, else a date in the run name).
    Untrusted: it only orders records the live repo cannot order by ancestry/commit time."""
    stamps = []
    for holder in (manifest, unit):
        if not isinstance(holder, dict):
            continue
        for cmd in holder.get("commands") or []:
            if isinstance(cmd, dict) and _epoch(cmd.get("ts")) is not None:
                stamps.append(_epoch(cmd.get("ts")))
        for key in ("recorded_at", "ts"):
            if _epoch(holder.get(key)) is not None:
                stamps.append(_epoch(holder.get(key)))
    if stamps:
        return max(stamps)
    found = re.search(r"(\d{4}-\d{2}-\d{2})", str(run_id))
    return _epoch(found.group(1) + "T00:00:00+00:00") if found else None


LEADING = re.compile(r"[ \t]*")


def _indent(line):
    """A line's leading indentation in COLUMNS, a tab advancing to the next multiple of eight as in
    Python's tokenizer. Every indentation comparison here goes through it (PR #639 review: the def
    was measured with tabs expanded and its body in raw characters, so a tab-indented method's
    body read as shallower than its def, was cut off, and a changed body stayed CURRENT)."""
    return len(LEADING.match(line).group().expandtabs())


@functools.lru_cache(maxsize=32)
def _python_tree(text):
    """The parsed module, or None when ``text`` is not source the parser accepts. Warnings (an
    invalid escape in someone's file) are the file's business, not the hint's output."""
    if text is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _rows(text):
    """Source rows as the parser numbers them: ``\\r\\n``, ``\\r`` and ``\\n`` end a row; a form feed
    or a Unicode line separator does not (str.splitlines() would shift every lineno after it)."""
    return re.split(r"\r\n|\r|\n", text)


def _definition_levels(scope):
    """The definitions under an ast ``scope``, one list per nesting depth: those reached through
    plain statements (if/try/with/for) first, then the ones nested inside each of those."""
    frontier = [scope]
    while frontier:
        level = []
        for owner in frontier:
            pending = list(ast.iter_child_nodes(owner))
            while pending:
                node = pending.pop()
                if isinstance(node, DEFINITIONS):
                    level.append(node)
                else:
                    pending.extend(ast.iter_child_nodes(node))
        if level:
            yield level
        frontier = level


def _python_definition(tree, symbol):
    """The ast node ``symbol`` names: each dotted part is looked up inside the previous part's node
    (``Cls.meth``, ``outer.inner``) at the shallowest depth that defines it, so ``balance`` is the
    module function, not ``Account.balance``. None when nothing defines it; AMBIGUOUS when that
    depth defines it twice (a redefinition, an if/else pair, a property setter)."""
    scope = tree
    for part in str(symbol).split("."):
        found = []
        for level in _definition_levels(scope):
            found = [node for node in level if node.name == part]
            if found:
                break
        if not found:
            return None
        if len(found) > 1:
            return AMBIGUOUS
        scope = found[0]
    return scope


def _unbounded(text, symbol):
    """True when Python text gives ``symbol`` no single block: it does not parse, or the name is
    ambiguous. Such a symbol is compared as the whole file, failing toward STALE."""
    tree = _python_tree(text)
    return tree is None or _python_definition(tree, symbol) is AMBIGUOUS


def _decorator_start(lines, i, indent):
    """Index of the first decorator line of the definition on lines[i] (i itself when none). A
    decorator is part of the definition: changing or adding one changes behavior with the body
    untouched (PR #639 review). Parsed Python answers from the definition's decorator list --
    exact through comments, left-aligned arguments and multiline strings. Other text walks up from
    the def (a heuristic): continuation lines of a multi-line decorator -- deeper-indented or a
    closing bracket -- are taken only when an ``@`` line at the def's own indentation opens them."""
    tree = _python_tree("\n".join(lines))
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, DEFINITIONS) and node.lineno == i + 1:
                return min([i] + [d.lineno - 1 for d in node.decorator_list])
    start, j = i, i - 1
    while j >= 0:
        stripped = lines[j].strip()
        depth = _indent(lines[j])
        if stripped.startswith("@") and depth == indent:
            start = j
        elif not (stripped == "" or depth > indent or stripped[0] in ")]}"):
            break
        j -= 1
    return start


def symbol_block(text, symbol):
    """The definition block of ``symbol``: its decorators through its last line; None when the
    text defines no such symbol. A qualified name (``Cls.meth``) resolves each part inside the
    previous one -- the class, then the method in it (PR #639 review: it used to search a literal
    ``def Cls.meth``). Text the Python parser accepts is bounded by it: the first decorator's row
    through ``end_lineno``, and a name it defines twice at one depth returns the whole text, so a
    comparison of it can only fail toward STALE. Any other text uses the indentation heuristic in
    _definition_block() (a def/class/function line through the next line indented no deeper)."""
    if text is None:
        return None
    tree = _python_tree(text)
    if tree is not None:
        node = _python_definition(tree, symbol)
        if node is None:
            return None
        rows = _rows(text)
        if node is AMBIGUOUS:
            return "\n".join(rows)
        start = _decorator_start(rows, node.lineno - 1, _indent(rows[node.lineno - 1]))
        return "\n".join(rows[start:node.end_lineno])
    block = text
    for part in str(symbol).split("."):
        block = _definition_block(block, part)
        if block is None:
            return None
    return block


def _definition_block(text, symbol):
    """The indentation heuristic for one unqualified name in non-Python text: the SHALLOWEST
    definition of it (first in the file among equals)."""
    if text is None or not symbol:
        return None
    lines = text.splitlines()
    pattern = re.compile(DEF_LINE.format(sym=re.escape(symbol)))
    hits = [(_indent(line), i) for i, line in enumerate(lines) if pattern.match(line)]
    if not hits:
        return None
    indent, i = min(hits)
    block = lines[_decorator_start(lines, i, indent):i + 1]
    for nxt in lines[i + 1:]:
        stripped = nxt.strip()
        if stripped and _indent(nxt) <= indent and not stripped.startswith((")", "}", "]")):
            break
        block.append(nxt)
    while block and not block[-1].strip():
        block.pop()
    return "\n".join(block)


def _inside(root, rel):
    """root/rel when it resolves inside root, else None (a record cannot name /etc/passwd)."""
    try:
        target = (Path(root) / rel).resolve()
        target.relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return None
    return target


class Archive:
    """The run archive a hint was drawn from: is the artifact still the bytes that were recorded?"""

    def __init__(self, runs_dir):
        self.runs_dir = Path(runs_dir)
        self.top = None
        if self.runs_dir.is_dir():
            try:
                proc = git(self.runs_dir, "rev-parse", "--show-toplevel")
            except (OSError, ProvenanceError):
                proc = None
            if proc is not None and _ok(proc) and proc.stdout.strip():
                self.top = Path(proc.stdout.strip())
        # Manifest evidence paths are repo-relative (evidence-manifest.md); outside git the
        # archive is laid out docs/runs/<run>/, so the repo root is two levels up.
        self.root = self.top or self.runs_dir.resolve().parent.parent

    def history_reasons(self):
        """[(UNKNOWN, "artifact-unversioned")] for an archive outside git: with no committed bytes
        to compare against, a copied or edited manifest cannot be told from the recorded one, so
        its revision and scope prove nothing (PR #639 review: it came out CURRENT). The same rule
        as an untracked manifest inside git."""
        return [] if self.top is not None else [(UNKNOWN, "artifact-unversioned")]

    def artifact_reasons(self, manifest_path, records):
        """[(label, reason)] for the artifact's own integrity: a tracked manifest whose bytes differ
        from its blob at the archive's HEAD, or an evidence file whose bytes no longer hash to the
        recorded sha256 (or cannot be read at all: unknown, not fatal)."""
        reasons = []
        if self.top is not None:
            rel = os.path.relpath(Path(manifest_path).resolve(), self.top.resolve())
            tracked = git(self.top, "ls-files", "--error-unmatch", "--", rel)
            if not _ok(tracked):
                reasons.append((UNKNOWN, "artifact-untracked"))
            else:
                reasons.extend(self._manifest_reasons(manifest_path, rel))
        seen = set()
        for record in records:
            for item in (record.get("artifacts") or []) if isinstance(record, dict) else []:
                if not isinstance(item, dict) or not isinstance(item.get("sha256"), str):
                    continue
                rel = normalize_path(item.get("path"))
                if not rel or rel in seen:
                    continue
                seen.add(rel)
                target = _inside(self.root, rel)
                try:
                    present = target is not None and target.is_file()
                    digest = sha256_file(target) if present else None
                except ArtifactRefused as exc:
                    reasons.append((UNKNOWN, f"artifact-{exc.kind}:{os.path.basename(rel)}"))
                    continue
                except OSError:
                    # Unknown for THIS hint only (PR #639 review: the OSError escaped every handler
                    # and one unreadable evidence file aborted the whole hint command).
                    reasons.append((UNKNOWN, f"artifact-unreadable:{os.path.basename(rel)}"))
                    continue
                if not present:
                    reasons.append((UNKNOWN, f"artifact-missing:{os.path.basename(rel)}"))
                elif digest != item["sha256"].removeprefix("sha256:").lower():
                    reasons.append((STALE, f"artifact-modified:{os.path.basename(rel)}"))
        return reasons

    def _manifest_reasons(self, manifest_path, rel):
        """The manifest's bytes against its blob at HEAD, compared directly. An empty ``git diff``
        is no evidence: an assume-unchanged or skip-worktree flag, or a stale stat cache, keeps git
        from reading the file (PR #639 review: an edited manifest kept its hint CURRENT). Hashed
        locally first; the blob is fetched only on a mismatch, and line endings alone are
        checkout conversion. Not committed at HEAD at all is a modification too."""
        committed = git(self.top, "rev-parse", f"HEAD:{rel}")
        blob_id = committed.stdout.strip() if _ok(committed) else ""
        if not blob_id:
            return [(STALE, "artifact-modified:manifest")]
        try:
            data = read_regular(manifest_path)
        except ArtifactRefused as exc:
            return [(UNKNOWN, f"artifact-{exc.kind}:manifest")]
        except OSError:
            return [(UNKNOWN, "artifact-unreadable:manifest")]
        if _blob_id(data, len(blob_id)) == blob_id:
            return []
        blob = git(self.top, "cat-file", "-p", blob_id, text=False)
        if not _ok(blob):
            return [(UNKNOWN, "artifact-unreadable:manifest")]
        if data.replace(b"\r\n", b"\n") != blob.stdout.replace(b"\r\n", b"\n"):
            return [(STALE, "artifact-modified:manifest")]
        return []


class LiveSource:
    """The checkout the current task runs against. ``rev=None`` reads the WORKING TREE (what the
    worker will see, uncommitted edits included) with HEAD for ancestry; a rev pins a commit."""

    def __init__(self, repo, rev=None):
        try:
            top = git(repo, "rev-parse", "--show-toplevel")
        except OSError as exc:
            raise ProvenanceError(f"live source {repo}: {exc}") from exc
        if not _ok(top) or not top.stdout.strip():
            raise ProvenanceError(f"live source {repo} is not a git checkout")
        self.root = Path(top.stdout.strip())
        self.worktree = rev is None
        head = git(self.root, "rev-parse", "--verify", f"{rev or 'HEAD'}^{{commit}}")
        if not _ok(head):
            raise ProvenanceError(f"live source {repo}: cannot resolve {rev or 'HEAD'}")
        self.rev = head.stdout.strip()
        self._cache = {}
        self._watched = {}

    def label(self):
        return f"repo={self.root.name} rev={self.rev[:12]}{'+worktree' if self.worktree else ''}"

    def _memo(self, key, compute):
        if key not in self._cache:
            self._cache[key] = compute()
        return self._cache[key]

    def has_commit(self, rev):
        return self._memo(("has", rev), lambda: _ok(git(self.root, "cat-file", "-e", f"{rev}^{{commit}}")))

    def is_ancestor(self, rev):
        return self._memo(("anc", rev), lambda: _ok(git(self.root, "merge-base", "--is-ancestor", rev, self.rev)))

    def descends_from_live(self, rev):
        return self._memo(("desc", rev), lambda: _ok(git(self.root, "merge-base", "--is-ancestor", self.rev, rev)))

    def commit_time(self, rev):
        def compute():
            proc = git(self.root, "log", "-1", "--format=%ct", rev, "--")
            return float(proc.stdout.strip()) if _ok(proc) and proc.stdout.strip().isdigit() else None
        return self._memo(("time", rev), compute)

    def exists_at(self, rev, path):
        return self._memo(("exists", rev, path), lambda: _ok(git(self.root, "cat-file", "-e", f"{rev}:{path}")))

    def text_at(self, rev, path):
        proc = git(self.root, "cat-file", "-p", f"{rev}:{path}", text=False)
        return proc.stdout.decode("utf-8", "replace") if _ok(proc) else None

    def live_text(self, path):
        if not self.worktree:
            return self.text_at(self.rev, path)
        target = _inside(self.root, path)
        try:
            if target is None or not target.is_file():
                return None
            return read_regular(target).decode("utf-8", "replace")
        except OSError as exc:
            # An unreadable live file is unknown for the hints scoped to it, not fatal to the rest.
            raise ProvenanceError(f"cannot read {path} in the live source") from exc

    def worktree_differs(self, rev, path):
        """Working-tree mode: do the bytes on disk for ``path`` -- a file, or every tracked file under
        a directory -- differ from ``rev``? ``git diff`` answers from the index, and an
        assume-unchanged or skip-worktree flag, or a stale stat cache, keeps it from looking at the
        file at all (PR #639 review), so an empty diff is never trusted for a path a hint depends
        on. True or False; None when no direct comparison is possible (unreadable, or nothing on
        disk: a sparse-checkout hole). A changed file outranks an unverifiable one in a directory.
        Submodules are left to the diff."""
        def compute():
            if path in self.tracked():
                kind = "blob"  # a tracked file the diff leaves out is the same blob at rev
            else:
                proc = git(self.root, "cat-file", "-t", f"{rev}:{path}")
                kind = proc.stdout.strip() if _ok(proc) else None
            if kind == "blob":
                files = [path]
            elif kind == "tree":
                prefix = path.rstrip("/") + "/"
                files = [rel for rel in self.tracked() if rel.startswith(prefix)]
            else:
                return False if kind == "commit" else None
            verdicts = set(self.files_differ(rev, files).values())
            return True if True in verdicts else (None if None in verdicts else False)
        return self._memo(("disk", rev, path), compute)

    def tracked(self):
        """Every tracked file in the index, submodules left out, listed once (ls-files -s): an
        ordered mapping, so it iterates in index order and answers membership directly."""
        def compute():
            listed = git(self.root, "ls-files", "-s", "-z")
            if not _ok(listed):
                raise ProvenanceError("cannot list tracked files in the live source")
            return dict.fromkeys(entry.split("\t", 1)[1] for entry in listed.stdout.split("\0")
                                 if "\t" in entry and not entry.startswith("160000 "))
        return self._memo(("tracked",), compute)

    def files_differ(self, rev, files):
        """{file: True | False | None} for tracked files against ``rev``, each memoized: the bytes on
        disk are hashed locally against the blob ids one rev-parse per 200 files reports, and the
        blob is fetched only on a mismatch, where a difference in line endings alone is checkout
        conversion, not an edit."""
        todo = [rel for rel in dict.fromkeys(files) if ("file", rev, rel) not in self._cache]
        ids = self._blob_ids(rev, todo)
        for rel in todo:
            self._cache[("file", rev, rel)] = self._file_differs(rel, ids.get(rel))
        return {rel: self._cache[("file", rev, rel)] for rel in files}

    def _file_differs(self, rel, blob_id):
        if blob_id is None:
            return None
        try:
            data = self._disk_bytes(rel)
        except OSError:
            return None
        if data is None:
            return None
        if _blob_id(data, len(blob_id)) == blob_id:
            return False
        blob = git(self.root, "cat-file", "-p", blob_id, text=False)
        if not _ok(blob):
            return None
        return data.replace(b"\r\n", b"\n") != blob.stdout.replace(b"\r\n", b"\n")

    def _blob_ids(self, rev, files):
        """{path: blob id at rev} for the paths rev-parse resolves; a chunk that fails is retried
        one path at a time, so one unresolvable path costs only itself."""
        ids = {}
        files = [rel for rel in files if "\n" not in rel]
        for start in range(0, len(files), 200):
            chunk = files[start:start + 200]
            proc = git(self.root, "rev-parse", *[f"{rev}:{rel}" for rel in chunk])
            found = proc.stdout.split() if _ok(proc) else []
            if len(found) == len(chunk):
                ids.update(zip(chunk, found, strict=True))
                continue
            for rel in chunk:
                one = git(self.root, "rev-parse", f"{rev}:{rel}")
                if _ok(one) and one.stdout.strip():
                    ids[rel] = one.stdout.strip()
        return ids

    def _disk_bytes(self, rel):
        """What git would hash for ``rel`` in the working tree: a symlink's target, a file's bytes;
        None when nothing is there. Confined to the checkout (a parent cannot point outside)."""
        parent = _inside(self.root, os.path.dirname(rel) or ".")
        if parent is None:
            return None
        leaf = parent / os.path.basename(rel)
        if leaf.is_symlink():
            return os.fsencode(os.readlink(leaf))
        try:
            return read_regular(leaf) if leaf.is_file() else None
        except ArtifactRefused:
            return None  # swapped for a link or a FIFO, or past MAX_READ_BYTES: no comparison, unknown

    def watch(self, rev, paths):
        """Name the paths a hint depends on -- its scope, its related tests, the dependency files: in
        working-tree mode changes_since(rev) compares each with the disk itself instead of trusting
        an empty diff for it."""
        self._watched.setdefault(rev, set()).update(paths)

    def changes_since(self, rev):
        """{path: (status, new_path)} from source rev to the live tree/rev, renames detected:
        a renamed path maps to ("R", its new name). In working-tree mode an UNTRACKED file is a
        change too (git diff never lists one): a new test or dependency file is part of what the
        worker will run against (PR #639 review). And a WATCHED path the diff leaves out is
        compared byte for byte (worktree_differs): ("M", None) when the disk differs from rev,
        ("?", None) when it cannot be compared -- the diff answers from the index, which an
        assume-unchanged or skip-worktree flag or a stale stat cache keeps from the file."""
        def compute():
            args = ["diff", "--no-ext-diff", "--no-textconv", "--name-status", "-M", "-z", rev]
            if not self.worktree:
                args.append(self.rev)
            proc = git(self.root, *args, "--")
            if not _ok(proc):
                raise ProvenanceError(f"cannot diff {rev[:12]} against the live source")
            fields = proc.stdout.split("\0")
            out, i = {}, 0
            while i < len(fields) and fields[i]:
                status = fields[i][0]
                if status in "RC":
                    old, new = fields[i + 1], fields[i + 2]
                    if status == "R":
                        out[old] = ("R", new)
                    out.setdefault(new, ("A", None))
                    i += 3
                else:
                    out[fields[i + 1]] = (status, None)
                    i += 2
            if self.worktree:
                extra = git(self.root, "ls-files", "--others", "--exclude-standard", "-z")
                if not _ok(extra):
                    raise ProvenanceError("cannot list untracked files in the live source")
                for path in filter(None, extra.stdout.split("\0")):
                    # Removed from the index yet present on disk: changed, not deleted.
                    out[path] = ("M", None) if out.get(path, ("A",))[0] == "D" else out.get(path, ("A", None))
            return out
        changes = self._memo(("diff", rev), compute)
        if not self.worktree:
            return changes
        out = dict(changes)
        pending = [path for path in sorted(self._watched.get(rev, ())) if _changed_under(changes, path) is None]
        if pending:
            # One batched pass fills the per-file memo; worktree_differs() then reads it.
            self.files_differ(rev, [path for path in pending if path in self.tracked()])
            for path in pending:
                differs = self.worktree_differs(rev, path)
                if differs is not False:
                    out[path] = ("M" if differs else "?", None)
        return out


def _blob_id(data, width):
    """The git object id of ``data`` as a blob, in the repository's hash (40 hex: sha1, else
    sha256) -- so an unchanged file costs no git call."""
    digest = hashlib.sha1 if width == 40 else hashlib.sha256
    return digest(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _changed_under(changes, path):
    """The change entry for path, or for anything under it when it names a directory."""
    if path in changes:
        return changes[path]
    prefix = path.rstrip("/") + "/"
    if any(changed.startswith(prefix) for changed in changes):
        return ("M", None)
    return None


def _scope_reasons(live, rev, paths, symbols):
    reasons = []
    live.watch(rev, [path for path in paths if live.exists_at(rev, path)])
    changes = live.changes_since(rev)
    for path in paths:
        if not live.exists_at(rev, path):
            reasons.append((UNKNOWN, f"scope-not-at-source:{path}"))
            continue
        entry = _changed_under(changes, path)
        if entry is None:
            continue
        status, new = entry
        if status == "?":
            reasons.append((UNKNOWN, f"scope-unverifiable:{path}"))
        elif status == "R":
            reasons.append((STALE, f"path-renamed:{path}->{new}"))
        elif status == "D":
            reasons.append((STALE, f"path-deleted:{path}"))
        elif symbols.get(path):
            reasons.extend(_symbol_reasons(live, rev, path, symbols[path]))
        else:
            reasons.append((STALE, f"path-changed:{path}"))
    return reasons


def _symbol_reasons(live, rev, path, names):
    """A changed file keeps a symbol-scoped hint CURRENT only while every named symbol's own
    definition block is byte-identical; a vanished symbol is a rename or deletion. A Python file
    that does not parse, or that defines the name twice, on either side has no trustworthy block:
    the whole file is compared instead (PR #639 review)."""
    reasons = []
    then, now = live.text_at(rev, path), live.live_text(path)
    python = path.lower().endswith(PYTHON_SUFFIXES)
    for name in sorted(names):
        if python and (_unbounded(then, name) or _unbounded(now, name)):
            whole = (STALE, f"path-changed:{path}")
            if then != now and whole not in reasons:
                reasons.append(whole)
            continue
        before, after = symbol_block(then, name), symbol_block(now, name)
        if before is None:
            reasons.append((STALE, f"path-changed:{path}"))
        elif after is None:
            reasons.append((STALE, f"symbol-gone:{path}::{name}"))
        elif before != after:
            reasons.append((STALE, f"symbol-changed:{path}::{name}"))
    return reasons


def _related_test(paths, record_tokens):
    """The related-test matcher: a test path (diff_scope's rule) outside the scope that the record
    named, or whose name contains a scoped file's stem. One definition for the diff-based check
    and the direct comparison of tracked files."""
    named = {normalize_path(t) for t in record_tokens if TEST_PATH.search(normalize_path(t))}
    stems = {os.path.splitext(os.path.basename(p))[0].lower() for p in paths}
    stems = {s for s in stems if len(s) >= 3}

    def matches(path):
        if path in paths or not TEST_PATH.search(path):
            return False
        return path in named or any(stem in os.path.basename(path).lower() for stem in stems)
    return matches


def _is_dependency(path):
    return os.path.basename(path).lower() in DEPENDENCY_FILES


def _named(kind, hits):
    return f"{kind}:{hits[0]}" + (f"+{len(hits) - 1}" if len(hits) > 1 else "")


def _related_test_reasons(changes, paths, record_tokens):
    """Tests the record named, or tests sharing a scoped file's stem, that changed since -- or that
    could not be compared with it (unknown, never fresh)."""
    related = _related_test(paths, record_tokens)
    hits = [p for p in sorted(changes) if related(p)]
    changed = [p for p in hits if changes[p][0] != "?"]
    unverifiable = [p for p in hits if changes[p][0] == "?"]
    return ([(STALE, _named("tests-changed", changed))] if changed else []) + \
        ([(UNKNOWN, _named("tests-unverifiable", unverifiable))] if unverifiable else [])


def _dependency_reasons(changes):
    hits = sorted(p for p in changes if _is_dependency(p))
    changed = [p for p in hits if changes[p][0] != "?"]
    unverifiable = [p for p in hits if changes[p][0] == "?"]
    return ([(UNKNOWN, _named("dependencies-changed", changed))] if changed else []) + \
        ([(UNKNOWN, _named("dependencies-unverifiable", unverifiable))] if unverifiable else [])


def assess(hint, live, archive=None):
    """Attach provenance-derived reasons to one prior-run hint (dict built by search_sessions).

    Reads hint["rev"], ["paths"], ["symbols"], ["tokens"], ["manifest_path"], ["records"];
    returns the list of (label, reason). Supersession needs every hint: see supersede()."""
    reasons = []
    rev = hint.get("rev")
    if rev is None:
        reasons.append((UNKNOWN, "revision-malformed" if hint.get("rev_raw") else "no-revision"))
    if archive is not None and hint.get("manifest_path"):
        reasons.extend(archive.history_reasons())
        reasons.extend(archive.artifact_reasons(hint["manifest_path"], hint.get("records") or []))
    if live is None:
        reasons.append((UNKNOWN, "no-live-source"))
        return reasons
    if rev is None:
        return reasons
    if not live.has_commit(rev):
        reasons.append((UNKNOWN, "revision-not-in-live-repo"))
        return reasons
    if not live.is_ancestor(rev):
        reasons.append((STALE, "ahead-of-live" if live.descends_from_live(rev) else "divergent-branch"))
        return reasons
    paths = hint.get("paths") or []
    if not paths:
        reasons.append((UNKNOWN, "scope-unresolved"))
    else:
        reasons.extend(_scope_reasons(live, rev, paths, hint.get("symbols") or {}))
    if live.worktree:
        # The related tests and dependency files git tracks get the same direct comparison as the
        # scope: a flagged or stat-hidden edit to them is missing from the diff too.
        related = _related_test(set(paths), hint.get("tokens") or [])
        live.watch(rev, [rel for rel in live.tracked() if _is_dependency(rel) or related(rel)])
    changes = live.changes_since(rev)
    reasons.extend(_related_test_reasons(changes, set(paths), hint.get("tokens") or []))
    reasons.extend(_dependency_reasons(changes))
    return reasons


# A record whose OWN provenance failed -- no or a foreign revision, a revision off the live line of
# history, an artifact that is not what was recorded -- proves nothing about what came after a
# valid record, so it never supersedes one (PR #639 review: an ahead-of-live record used to hide
# the checkout's valid record, and current mode then showed neither).
DISQUALIFYING = ("no-revision", "revision-malformed", "revision-not-in-live-repo", "divergent-branch",
                 "ahead-of-live", "artifact-", "provenance-unreadable")


def provenance_failed(hint):
    return any(reason.startswith(DISQUALIFYING) for _label, reason in hint.get("reasons") or [])


def _newer(a, b, live):
    """True when record b is strictly newer than record a: by ancestry when the live repo knows
    both revisions, else by commit time, else by the records' own claimed time. Two runs at ONE
    revision share a commit time, so the claimed time breaks that tie (PR #639 review: a later
    run reversing an earlier verdict on unchanged code left both CURRENT)."""
    ra, rb = a.get("rev"), b.get("rev")
    if live is not None and ra and rb and ra != rb and live.has_commit(ra) and live.has_commit(rb):
        if _ok(git(live.root, "merge-base", "--is-ancestor", ra, rb)):
            return True
        if _ok(git(live.root, "merge-base", "--is-ancestor", rb, ra)):
            return False
    ta, tb = a.get("time"), b.get("time")
    if ta is not None and tb is not None and ta != tb:
        return tb > ta
    ca, cb = a.get("claimed", ta), b.get("claimed", tb)
    return ca is not None and cb is not None and cb > ca


def supersede(hints, live, observations=()):
    """Contradictory evidence (#605): a hint is SUPERSEDED when a strictly newer record of the
    same unit claims the opposite outcome, when a newer record lists it in ``supersedes``, or when
    a CURRENT observation of its scope (the frozen task's own evidence) says the opposite. Only a
    record whose own provenance held can supersede (provenance_failed). A contradicting record
    that nothing orders either way -- same revision, same or no claimed time -- leaves both
    UNKNOWN: neither verdict is known to hold. Mutates each hint's ``reasons``; a contradiction
    only ever demotes, never promotes."""
    for old in hints:
        unordered = None
        for new in hints:
            if new is old or provenance_failed(new):
                continue
            names = {str(s).strip().lower() for s in new.get("supersedes") or []}
            explicit = old["unit_key"] in names or f"{old['run_key']}/{old['unit_key']}" in names
            contradicts = (old["unit_key"] == new["unit_key"] and old.get("outcome") and new.get("outcome")
                           and old["outcome"] != new["outcome"])
            if (explicit or contradicts) and _newer(old, new, live):
                old["reasons"].append((SUPERSEDED, f"superseded-by:{new['run']}/{new['unit']}"))
                unordered = None
                break
            if contradicts and unordered is None and not _newer(new, old, live):
                unordered = new
        if unordered is not None:
            old["reasons"].append((UNKNOWN, f"contradicted-by:{unordered['run']}/{unordered['unit']}"))
        for obs in observations:
            if not old.get("outcome") or obs["outcome"] == old["outcome"]:
                continue
            if any(match_kind(p, obs["path"]) for p in old.get("paths") or []):
                old["reasons"].append((SUPERSEDED, f"current-evidence:{obs['path']}={obs['outcome']}"))
                break


def verdict(reasons):
    """(label, ordered reasons): the worst reason wins; no reason at all is CURRENT."""
    if not reasons:
        return CURRENT, []
    ordered = sorted(reasons, key=lambda r: -SEVERITY[r[0]])
    return ordered[0][0], [r for _label, r in ordered]


def load_observations(raw):
    """Validate the frozen task's current evidence: [{path, outcome: pass|fail, source?}]."""
    items = raw.get("observations") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ProvenanceError("current evidence must be a list or {observations: [...]}")
    out = []
    for i, item in enumerate(items):
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"].strip()
                or item.get("outcome") not in ("pass", "fail")):
            raise ProvenanceError(f"current evidence [{i}] needs a path and outcome pass|fail")
        out.append({"path": normalize_path(item["path"]), "outcome": item["outcome"],
                    "source": str(item.get("source") or "")})
    return out
