#!/usr/bin/env python3
"""Diff-scoped floor guard: the cheap road to green, caught mechanically.

Six moves lower the bar without touching a stated requirement: a silenced
checker, a test made easier, unfinished work left as a stub, an assertion
deleted from a test that stayed, a threshold walked down in the constraints
file (or a new exception row admitted beside it), and a touch to the frozen
guard surface (the tool-config the bar stands on). Each is invisible to a green
build and obvious in a diff. This guard reads the diff.

Scope is the merge base against ``--base`` plus the working tree plus untracked
files -- a guard that reads only ``git diff`` misses the new file. Tightening is
silent; loosening is loud: only moves that lower the bar are reported.

Rules (rule ids are stable; a waiver names one):

===================  ============================================================
rule id              what trips it (added lines unless stated)
===================  ============================================================
silenced-checker     ``# noqa``, ``eslint-disable``, ``@ts-ignore``, ``@ts-nocheck``,
                     ``# type: ignore``, ``pragma: no cover``, ``biome-ignore``,
                     ``istanbul ignore``, ``nosemgrep``, ``gitleaks:allow``,
                     ``#[allow(``, ``nolint``, ``Stryker disable``, ``prettier-ignore``
test-made-easier     ``@skip``, ``.skip(``, ``.only(``, ``.todo(``, ``xit(``,
                     ``xdescribe(``, ``pytest.mark.skip``, ``pytest.mark.xfail``,
                     ``unittest.skip``, ``t.Skip(``, ``@Ignore``, ``return  # stub``
                     -- plus the call forms (``self.skipTest``, raising ``SkipTest``,
                     ``t.Skipf``, ``pytest.skip``/``pytest.xfail`` called), and a
                     test def renamed out of discovery in the same file
                     (``test_x`` removed, ``_test_x``/``disabled_test_x`` added)
unfinished-work      ``TODO``/``FIXME``/``XXX``, ``NotImplementedError``,
                     ``not implemented``, an empty ``catch``/``except: pass``,
                     a ``TODO``-return (``return None  # TODO``)
assertion-removed    a REMOVED line carrying ``assert``, ``expect(``, ``should``,
                     ``self.assert``, ``t.Error`` in a path that looks like a test
                     and still exists at HEAD. A deleted test file is not this rule
                     -- unless half its lines reappear elsewhere in the diff (a
                     rename or move under ``--no-renames``): then each assertion not
                     re-added in a test path is charged to the destination
threshold-lowered    a numbered row of the constraints file whose number went DOWN,
                     matched in order by the row/bullet key left of the first ``|``
                     or ``:`` -- a numbered row deleted, re-keyed (``D1`` -> ``D1b``)
                     or with its number worded away is the same move
new-exception        an added constraints row shaped ``| W123 |`` / ``| E45 |``, or
                     an added line under an ``## Exceptions`` heading
guard-surface        an added/removed line touching CONSTRAINTS.md's frozen guard
                     surface (whole files: any line; keyed files: the key's
                     assignment — for ruff.toml the rule selection and every key
                     that carves it back, for .coveragerc fail_under, the scope
                     keys and their continuation lines —
                     assignment only — a use-site or comment stays silent)
===================  ============================================================

Exemptions come from the DECISIONS log, never from an ignore file. A waiver is a
record whose ID is ``floor-waiver:<rule>:<path-or-glob>`` and whose ANSWER
grants -- a bare directory is not a waiver, and neither is ``**``. Scope in the
id gives the waiver an identity the ledger can retire, so a later ``superseded``
row ends it exactly as it ends any other decision, and ``decisions.active``
decides which waivers still stand. No prose is parsed: a sentence that mentions
a rule and a path is not a waiver (#313, PR #308 review).

A waiver is read from the BASE ref's ledger (``git cat-file`` of ``<base>:docs/DECISIONS.md``),
never from the tree under review: a change cannot write its own exemption, so a waiver lands on
the base branch first (2026-10-23 review, P1-7). And it grants only as a one-way human grant --
class ``one-way``, a ``[source=human:<name>]`` suffix, and, when the base ref pins
``.orca/human-grant-pubkey``, a signature that verifies (decisions.py ``grant_problems``, the
same check ``decisions.py check`` runs). CONSTRAINTS.md says the bar moves only by a one-way
human decision; a ``taste`` or ``mechanical`` ``allow``, including every waiver recorded before
this rule, no longer grants -- by design. The guard names such a line when it is the only thing
standing between a finding and a waiver.

Every diff is taken with ``--text`` and ``--no-color`` and pins the prefix and colour keys on
its own command line (``DIFF_RENDERING``): a ``.gitattributes`` ``-diff`` (or a NUL byte)
rendered every touched file as ``Binary files differ`` and blanked every rule (P1-6), and a
repo-local prefix or colour setting hid every path from the parser (P2-4). C-quoted header
paths (non-ASCII, quotes, control bytes) are decoded, so a quoted test path is not mistaken
for a deleted one (P2-6).
CONSTRAINTS.md stays out of the whole-file guard surface on purpose: the threshold rules
above already catch every way a numbered row can lose its number, and a whole-file surface
would demand a pre-landed one-way waiver for a dated evidence note or a typo fix.

Reporting is redaction-first: rule id, ``file:line`` and a short pattern name --
never the matched text, which may be the credential someone tried to suppress.

Exit codes
    0  clean
    1  at least one un-waived finding (block the change)
    2  the guard could not run -- not a git repo, no merge base, unreadable
       waiver file or malformed base-ref grant key. Never let a 2 read as a 0.

How to wire
    Run it OFF the worker, never inside the builder loop: a guard the builder can
    see is a guard the builder edits. Two consumers. (1) A GUARD unit in the
    floor-it mission runs it against the unit's base and treats exit 1 as the
    unit's failing oracle -- the script IS the reviewed CI unit. (2) An
    independent verifier runs it over a mutation unit's diff before any
    judgement-based review: a diff that trips ``test-made-easier`` or
    ``assertion-removed`` fails the negative-control leg deterministically, so a
    disabled test cannot hide behind a hand-written negative-control note. Exit 2
    parks the unit (a shallow CI checkout must not present as a clean floor).
    It is regex-shallow by design: a floor under review, never a replacement for it.

    Example: ``floor_guard.py --base origin/main --constraints CONSTRAINTS.md``
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
import importlib.util
import re
import unicodedata
import subprocess
from collections import Counter
from pathlib import Path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CANNOT_RUN = 2

# (pattern name, compiled regex). The name is what gets reported; the matched
# text never is.
SUPPRESSIONS = [
    ("noqa", re.compile(r"#\s*noqa")),
    ("type-ignore", re.compile(r"#\s*type:\s*ignore")),
    ("pragma-no-cover", re.compile(r"pragma:\s*no\s*cover")),
    ("eslint-disable", re.compile(r"eslint-disable")),
    ("ts-ignore", re.compile(r"@ts-(ignore|nocheck|expect-error)")),
    ("biome-ignore", re.compile(r"biome-ignore")),
    ("istanbul-ignore", re.compile(r"istanbul\s+ignore")),
    ("nosemgrep", re.compile(r"nosemgrep")),
    ("gitleaks-allow", re.compile(r"gitleaks:allow")),
    ("rust-allow", re.compile(r"#\[allow\(")),
    ("golangci-nolint", re.compile(r"//\s*nolint")),
    ("stryker-disable", re.compile(r"Stryker\s+disable")),
    ("prettier-ignore", re.compile(r"prettier-ignore")),
    ("phpstan-ignore", re.compile(r"@phpstan-ignore")),
]

SKIPS = [
    ("pytest-skip", re.compile(r"@?pytest\.mark\.(skip|skipif|xfail)")),
    ("unittest-skip", re.compile(r"@?unittest\.(skip|expectedFailure)")),
    # The imperative forms skip from inside a test body (2026-10-23 review, section 5).
    ("skiptest-call", re.compile(r"\bskipTest\s*\(")),
    ("raise-skiptest", re.compile(r"\braise\s+(?:\w+\.)*SkipTest\b")),
    ("pytest-skip-call", re.compile(r"\bpytest\.(skip|xfail)\s*\(")),
    ("decorator-skip", re.compile(r"^\s*@(skip|Skip|Ignore|Disabled)\b")),
    ("dot-skip", re.compile(r"\.(skip|only|todo|failing)\s*\(")),
    ("xit", re.compile(r"\bx(it|describe|test|context)\s*\(")),
    ("go-skip", re.compile(r"\b[tb]\.Skip(Now|f)?\s*\(")),
    ("rust-ignore", re.compile(r"#\[ignore")),
    ("junit-ignore", re.compile(r"@(Ignore|Disabled)\b")),
]

STUBS = [
    ("todo-marker", re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")),
    ("not-implemented", re.compile(r"(NotImplementedError|not\s+implemented|unimplemented!)")),
    ("empty-catch", re.compile(r"catch\s*(\([^)]*\))?\s*\{\s*\}")),
    ("swallowed-except", re.compile(r"except[^:]*:\s*pass\b")),
    ("stub-return", re.compile(r"return\s+(None|null|nil|\{\}|\[\]|\"\"|'')\s*(#|//)\s*(TODO|stub)")),
    ("pass-stub", re.compile(r"\bpass\s*(#|//)\s*stub")),
]

ASSERTIONS = re.compile(r"(\bassert\b|\bexpect\s*\(|\bshould\b|self\.assert|\bt\.Error)")
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__)/|\.(test|spec)\.|_test\.|(^|/)test_[^/]*$")
# Binary media no checker, linter or test runner ever reads as code. The diff is taken with
# --text (P1-6), so an image or archive renders as bytes, and a random run of bytes spelled a
# stub marker or a suppression: a re-rendered JPEG tripped unfinished-work (PR #631 rename). The
# content rules skip these by EXTENSION, never by a NUL byte — a NUL in a source file is the
# evasion --text closed. Path rules (the guard surface) still see every file.
BINARY_MEDIA = frozenset((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif",
                          ".tiff", ".avif", ".heic", ".mp4", ".mov", ".webm", ".mp3", ".wav",
                          ".ogg", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".zip", ".gz",
                          ".tgz", ".xz", ".bz2", ".7z", ".jar", ".pyc"))
EXCEPTION_ROW = re.compile(r"^\s*\|\s*[WE]\d+\s*\|")
EXCEPTIONS_HEADING = re.compile(r"^\s*#{1,6}\s+.*\bexceptions?\b", re.IGNORECASE)
NUMBER = re.compile(r"\d+(?:\.\d+)?")
# A test definition by name (Python def/class, Go func). A runner discovers by the name's
# prefix, so a discovered name that loses its prefix while the body stays is a disabled test.
TEST_DEF = re.compile(r"^\s*(?:async\s+def|def|class|func)\s+([A-Za-z_]\w*)")
DISCOVERY_PREFIXES = ("test", "Test")
# A deleted test file whose lines mostly reappear elsewhere was moved, not deleted. Half is
# git's own default rename threshold (-M50%); a substantive line is long enough not to be
# boilerplate like `)` or `pass`.
MOVE_SIMILARITY = 0.5
SUBSTANTIVE_LEN = 6

# Frozen guard surface (CONSTRAINTS.md "Guard surface", Q4-confirmed, plus the
# D9-flagged .coveragerc fail_under): the tool-config the bar stands on. A diff
# line touching it fails without a `floor-waiver:guard-surface:<path>` grant.
# Whole files trip on ANY added/removed line — every line of .gitleaksignore is
# a waiver, every routing prompt and every trap is load-bearing. Keyed files trip
# only on the key's ASSIGNMENT (`name = ...`): the floor is the value, not a
# use-site or a comment about it — tests/test_evals.py cites its floor constant
# on lines that do not move the floor, and those must stay silent. Matching is
# path-gated throughout, so this very source file (which must name each key to
# guard it) and any doc that cites one are never their own finding.
GUARD_SURFACE_FILES = (
    ".gitleaksignore",
    # A path allowlist here waives every finding in the paths it names (2026-10-27 security
    # audit, W6-03): a waiver mechanism, so it moves only with a recorded human grant.
    ".gitleaks.toml",
    "evals/routing.json",
    "bench/vf-bench/VERSION",
    "bench/vf-bench/CANARY",
)
GUARD_SURFACE_DIRS = ("bench/vf-bench/traps/",)
GUARD_SURFACE_KEYS = (
    # (path, assignment regex): the ruff rule selection AND everything that carves it back
    # (ignore, extend-*, exclude, per-file-ignores and their entries, a rule code on its own
    # line in a multi-line list — 2026-10-26 review: `ignore = ["F821"]` beside the guarded
    # select lowered the bar in silence), the coverage fail_under AND its scope (source, include,
    # omit, exclude_lines and the indented continuation lines those INI values are written on),
    # the routing floor, and the vf-bench pins (VERSION + CANARY + traps digest as enforced in
    # gate.py — a corpus bump moves them in the same PR, explicitly).
    ("ruff.toml", re.compile(r"^\s*(extend-)?(select|ignore|exclude|fixable|unfixable)\s*=")),
    ("ruff.toml", re.compile(r"^\s*\[[^\]]*per-file-ignores")),
    # A table entry and a rule code on its own line, in either TOML quote style, and a bare key
    # assigned a list of rule codes (#707 review: `'runtime/scripts/*' = ['F401']` matched none).
    ("ruff.toml", re.compile(r"^\s*(\"[^\"]+\"|'[^']+')\s*=")),
    ("ruff.toml", re.compile(r"^\s*(\"[A-Z]+[0-9]*\"|'[A-Z]+[0-9]*')\s*,?\s*$")),
    ("ruff.toml", re.compile(r"^\s*[A-Za-z0-9_.*/-]+\s*=\s*\[\s*[\"'][A-Z]+[0-9]*[\"']")),
    (".coveragerc", re.compile(r"^\s*(fail_under|source|include|omit|exclude_lines|exclude_also|"
                               r"skip_covered|skip_empty|ignore_errors|partial_branches|plugins)\s*=")),
    (".coveragerc", re.compile(r"^\s+[^\s#;]")),
    ("tests/test_evals.py", re.compile(r"\bROUTING_MIN_SCORE\s*=")),
    ("bench/vf-bench/gate.py", re.compile(r"\bEXPECTED_VERSION\s*=")),
    ("bench/vf-bench/gate.py", re.compile(r"\bEXPECTED_CANARY_GUID\s*=")),
    ("bench/vf-bench/gate.py", re.compile(r"\bEXPECTED_CORPUS_SHA256\s*=")),
)

# Diff RENDERING pins, at command-line precedence over the guarded repo's own config
# (2026-10-23 review, P2-4). A repo-local `diff.mnemonicPrefix` (c/ i/ w/), `diff.srcPrefix`/
# `dstPrefix` or `diff.noprefix` relabels the a/ b/ that strip_prefix removes, so every path
# missed its rule; `noprefix` must be pinned beside the prefixes because git lets it win.
# `color.diff` is pinned as well as passing --no-color. These live in this diff argv, not in
# gitexec.py's shared env: floor_guard is the one gitexec caller that parses a diff
# (diff_scope.py inlines its own env and reads -z --name-only), and gitexec's env stays about
# execution channels and object identity. `diff.external` is --no-ext-diff below.
DIFF_RENDERING = (
    "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
    "-c", "diff.srcPrefix=a/", "-c", "diff.dstPrefix=b/",
    "-c", "diff.relative=false", "-c", "color.diff=false",
)


def _sibling(name):
    """Load a runtime/scripts sibling by path (no sys.path edits)."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_diffparse = _sibling("diffparse")
gitexec = _sibling("gitexec")


class GuardError(Exception):
    """Raised for every could-not-run condition; the caller maps it to exit 2."""


def _text(raw):
    # Bytes in, text out with line endings untouched: text=True would apply
    # universal newlines and turn a bare \r inside file content into an extra
    # line, which the hunk-counted parser then rejects as a malformed patch.
    return raw.decode("utf-8", "replace")


def git(repo, *args, blanks=(), custody=None):
    """Run git with argv only. Returns stdout, or None when git exits non-zero. ``blanks`` are
    gitexec.driver_blanks pairs, carried in the env so a driver name reaches git byte-exact.
    Every call runs under gitexec.custody_env (no lazy fetch, no transport but `file`, no
    signature or submodule child, no inherited repository selector); ``custody`` (a
    gitexec.Custody) runs it against the coordinator-built git dir instead of ``repo``'s own."""
    lead = custody.lead if custody is not None else ["-C", str(repo)]
    pairs = [*(custody.pairs if custody is not None else ()), *blanks]
    try:
        # A config, include or `shallow` git would block opening is refused before git runs.
        gitexec.refuse_blocking_files(repo)
        # No stdin (#629): an inherited, never-closed one would let a hook or filter block the guard.
        r = subprocess.run(
            gitexec.argv(*lead, *args),
            capture_output=True, timeout=60, env=gitexec.custody_env(blanks=pairs),
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as err:
        raise GuardError(f"git {' '.join(args)} failed to run: {err}") from err
    # surrogateescape, not _text's "replace": two refnames that differ only in non-UTF-8 bytes
    # (zz\xff, zz\xfe) must not decode alike, or the anchor listing refuses itself (W3-07).
    return r.stdout.decode("utf-8", "surrogateescape") if r.returncode == 0 else None


def repo_root(start):
    top = git(start, "rev-parse", "--show-toplevel")
    if not top or not top.strip():
        raise GuardError(f"{start} is not inside a git work tree")
    return Path(top.strip())


def resolve_base(repo, base):
    """(commit, shown): the base resolved ONCE, by exact ref names only (gitexec.base_commit,
    W3-07 class). The diff, the waivers and the human-grant pin are all read at `commit`, never at
    the name. An explicit --base that does not resolve is an error, not a fallback: silently
    guarding against the wrong base is a false clean.

    `rev-parse <base>^{commit}` expanded the name — refs/tags/ and refs/heads/ come before
    refs/remotes/ — so a tag or local branch spelled `origin/main` stood in for the remote-tracking
    branch, and this base is where the waivers are read; an origin/HEAD pointed at a local branch
    was used as-is. Now a remote-tracking name (`origin/main`, `refs/remotes/…`) or a commit id
    goes through gitexec.remote_tracking_commit; a bare `main` is that local branch by its exact
    name, and `HEAD` or an abbreviated commit id (an object id, never a ref of that spelling) is
    the same advisory kind — refused on a lane claiming soundness (gitexec.sound_lane:
    ORCA_PROVENANCE / OPEN_FLEET_PROVENANCE set, as decisions.py and run_report.py read it), and
    said in a NOTE to be advisory elsewhere (the change can move a local name)."""
    def run(*args):
        out = git(repo, *args)
        return (0, out) if out is not None else (1, "")

    commit, shown, local, why = gitexec.base_commit(run, base)
    if commit is None:
        if base:
            raise GuardError(f"base ref {base!r} is not resolvable by its exact name (shallow clone "
                             f"or missing fetch?): {base!r} {why}")
        raise GuardError(f"no base ref could be resolved (tried {shown}): {why}")
    if local:
        lane = gitexec.sound_lane()
        if lane:
            raise GuardError(f"{lane} claims a sound lane, but base {shown!r} is {local} "
                             f"({commit[:12]}), not a remote-tracking ref or a full commit id: "
                             "there the waivers and the human-grant pin are read only at one of "
                             "those — --base origin/<branch> or a full commit id (W3-07)")
        print(f"floor-guard: NOTE — base {shown!r} is {local} ({commit[:12]}), not a "
              "remote-tracking ref or a full commit id: the change under check can move a local "
              "name and nothing binds an abbreviation, so the waivers and the human-grant pin read "
              "there are advisory; --base origin/<branch> (or a full commit id) reads them where "
              "it cannot write", file=sys.stderr)
    return commit, shown


def merge_base(repo, base):
    mb = git(repo, "merge-base", base, "HEAD")
    if not mb or not mb.strip():
        raise GuardError(f"no merge base between {base} and HEAD")
    return mb.strip()


def collect_diff(repo, mb):
    """Unified-0 diff against the merge base, plus every untracked file rendered
    as an all-added diff. Returns the concatenated diff text.

    Rename detection stays OFF: a content-preserving rename (similarity 100%)
    otherwise renders as `rename from/to` metadata with no content lines, and a
    content-line guard reads that as silence — renaming .coveragerc sideways
    would unwire D9 without tripping a thing (PR #468 review, P1). As delete +
    add, the removed half trips every whole-file and keyed rule it touches.

    ``--text`` on BOTH diffs (2026-10-23 review, P1-6): without it git honours the tree's
    own ``.gitattributes``, so a change adding ``* -diff`` rendered every file -- tracked
    and untracked -- as ``Binary files … differ`` with no content lines, and every rule
    went silent. Content sniffing is the same hole (one NUL byte makes a config file
    "binary"), so every file is read as text. ``--no-color`` beside DIFF_RENDERING's pins:
    a coloured hunk header is not a hunk header to the parser.
    """
    diff_options = ("--no-ext-diff", "--no-textconv", "--no-renames", "--text", "--no-color",
                    "--unified=0")
    # A diff of the working tree runs a clean filter (and could run a textconv or diff driver)
    # that a .gitattributes or $GIT_DIR/info/attributes line selects — the exec channel
    # --no-ext-diff/--no-textconv do NOT close (#629). Listing the drivers the repo declares and
    # blanking them is not enough: a worker adding a new one between that listing and the diff
    # had it run (W4 custody sweep). So both diffs run in git custody (gitexec.custody): against a
    # git dir the guard builds over the repo's objects and index, whose config declares no driver,
    # with the repo's own work tree. A selected driver is undefined there, whenever it was added,
    # and no child git is started inside a checked-out submodule (gitexec.NO_SUBMODULE_CHILD).
    # The listing stays as a belt and keeps its fail-closed contract: an unreadable driver list is
    # could-not-run, never "no drivers" (PR #649 review).
    try:
        gitexec.refuse_blocking_files(repo)
    except OSError as err:
        raise GuardError(f"git would block reading this repository: {err}") from err
    try:
        blanks = gitexec.driver_blanks(repo)
    except gitexec.DriverQueryFailed as err:
        raise GuardError(f"cannot read the repository's driver config, so its filter commands "
                         f"cannot be neutralised: {err}") from err
    try:
        with gitexec.custody(repo) as custody:
            # NO_SUBMODULE_CHILD: a checked-out submodule's dirtiness is never probed (that is a
            # child git under the submodule's own config); a moved gitlink still shows.
            tracked = git(repo, *DIFF_RENDERING, "diff", *diff_options, gitexec.NO_SUBMODULE_CHILD,
                          mb, "--", blanks=blanks, custody=custody)
            if tracked is None:
                raise GuardError("tracked/staged diff acquisition failed")
            # Lists names, reads no file content, but reads the ignore files: in custody, where the
            # repository's own core.excludesFile is carried as data and no user default is opened.
            others = git(repo, "ls-files", "-z", "--others", "--exclude-standard", custody=custody)
            if others is None:
                raise GuardError("untracked file enumeration failed")
            chunks = [tracked]
            for name in others.split("\0"):
                if not name:
                    continue
                # --no-index exits 1 when the files differ; that is the normal case, so
                # go through subprocess directly rather than git() (which returns None).
                try:
                    r = subprocess.run(
                        custody.argv(*DIFF_RENDERING, "diff", "--no-index",
                                     *diff_options, "--", "/dev/null", name),
                        capture_output=True, timeout=60, env=custody.env(blanks=blanks),
                        stdin=subprocess.DEVNULL,
                    )
                except (OSError, subprocess.SubprocessError) as err:
                    raise GuardError("untracked diff acquisition failed to run") from err
                # Git also exits 1 for inaccessible input, with no acquired patch. A
                # successful difference must have output; exit 0 may legitimately be empty.
                if r.returncode not in (0, 1) or (r.returncode == 1 and not r.stdout):
                    raise GuardError(f"untracked diff acquisition failed (exit {r.returncode})")
                chunks.append(_text(r.stdout))
    except gitexec.GitCustodyRefused as err:
        raise GuardError(f"cannot diff the working tree in git custody: {err}") from err
    except (OSError, subprocess.SubprocessError) as err:
        raise GuardError(f"git custody could not run: {err}") from err
    return "\n".join(chunks)


def parse_diff(diff_text):
    """Split a unified diff into (added, removed) lists of (path, lineno, text).

    Hunk-counted (diffparse.records): a removed content line whose text starts
    `-- ` is `--- ...` on the wire, and reading it as a file header used to move
    every later finding in the hunk onto a file named by that content. A diff
    whose hunks do not add up is a could-not-run, never a partial read.
    """
    added, removed = [], []
    new_path = old_path = ""
    new_no = old_no = 0
    try:
        for kind, line, match in _diffparse.records(diff_text):
            if kind == "header":
                if line.startswith("--- "):
                    old_path = strip_prefix(line[4:])
                elif line.startswith("+++ "):
                    new_path = strip_prefix(line[4:])
            elif kind == "hunk":
                old_no = int(match.group(1))
                new_no = int(match.group(3))
            elif kind == "+":
                added.append((new_path or old_path, new_no, line[1:]))
                new_no += 1
            elif kind == "-":
                removed.append((old_path or new_path, old_no, line[1:]))
                old_no += 1
            elif kind == " ":
                new_no += 1
                old_no += 1
    except ValueError as err:
        raise GuardError(f"diff is not a well-formed unified diff: {err}") from err
    return added, removed


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
_C_OCTAL = re.compile(r"[0-3][0-7]{2}")


def unquote_c(text):
    """Decode a git C-quoted path (``"a/t\\303\\251st.py"``); an unquoted one passes through.

    git quotes a header path holding non-ASCII bytes, a quote, a backslash or a control
    byte. Read raw, the quotes and escapes became part of the path, the existence check
    missed it, and a surviving test that lost an assertion read as deleted (2026-10-23
    review, P2-6). A malformed escape is not something git writes: ValueError."""
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        return text
    body, out, i = text[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
        elif body[i + 1:i + 2] in _C_ESCAPES:
            out.append(_C_ESCAPES[body[i + 1]])
            i += 2
        elif _C_OCTAL.fullmatch(body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            raise ValueError(f"malformed C-quoted path in a diff header: {text[:80]!r}")
    return out.decode("utf-8", "replace")


def strip_prefix(path):
    # git appends a TAB to a header path that holds a space; strip() takes it with the rest.
    path = unquote_c(path.strip())
    if path.startswith(("a/", "b/")):
        return path[2:]
    if path == "/dev/null":
        return ""
    return path


def is_constraints(path, constraints_name):
    return bool(path) and Path(path).name == Path(constraints_name).name


# Not thresholds: ISO dates, issue refs and upper-case row ids (D9, G1, P1-7, W101) — counted as
# numbers they made a re-dated note read as a lowered floor and an edited id as a dropped one.
# A lower-case prefix (v1.2) stays a number: version pins are compared like any other value.
_NOT_A_THRESHOLD = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[\d:]+Z?)?|#\d+|\b[A-Z]+\d+(?:[.-][A-Za-z0-9]+)*")
# A cell that states a floor: a comparator, or the words a floor is stated with.
_FLOOR_WORDS = re.compile(r">=|<=|≥|≤|\bfloor\b|\bthreshold\b|\beffective\b|\bminimum\b|\bat least\b|"
                          r"\bno (?:lower|less|fewer)\b", re.IGNORECASE)
_COMPARATOR_NUMERIC = re.compile(r"(?:>=|<=|≥|≤|>|<)\s*=?\s*\d")
_COMPARATOR = re.compile(r">=|<=|≥|≤|>|<")


def numbers(text):
    """The threshold-shaped numbers of a line: NFKC-folded (a full-width ８０ is 80), with dates,
    issue refs and letter-prefixed identifiers set aside (2026-10-26 review)."""
    folded = unicodedata.normalize("NFKC", text)
    return [float(n) for n in NUMBER.findall(_NOT_A_THRESHOLD.sub(" ", folded))]


# A number and the unit written right after it (`80%`, `200 ms`, `100 cases`), or "".
_NUMBER_UNIT = re.compile(r"(\d+(?:\.\d+)?)\s?(%|[A-Za-z]+)?")


def numbers_with_units(text):
    """`numbers(text)`, each paired with the unit that follows it (#707 review)."""
    folded = unicodedata.normalize("NFKC", text)
    return [(float(n), unit.lower()) for n, unit in _NUMBER_UNIT.findall(_NOT_A_THRESHOLD.sub(" ", folded))]


def cells(text):
    """A table row's cells (the outer pipes stripped), or the whole line as one cell."""
    folded = unicodedata.normalize("NFKC", text).strip()
    if folded.startswith("|"):
        return [c.strip() for c in folded.strip("|").split("|")]
    return [folded]


def guard_surface_hit(path, text):
    """Name the frozen-surface item a diff line touches, or None.

    Whole files and trap-dir members trip on any line; keyed files only on the
    key's assignment. The name is what gets reported; the matched text never is.
    """
    if not path:
        return None
    if path in GUARD_SURFACE_FILES:
        return path
    for surface_dir in GUARD_SURFACE_DIRS:
        if path.startswith(surface_dir):
            return surface_dir.rstrip("/")
    for surface_file, assignment in GUARD_SURFACE_KEYS:
        if path == surface_file and assignment.search(text):
            return surface_file
    return None


def row_key(text):
    """Identify a constraints row so its before/after pair can be matched.

    The key is the first NON-EMPTY cell: a markdown table row starts with the
    delimiter, so splitting naively yields an empty first field and every row
    keys the same, which silently disables the comparison.
    """
    folded = unicodedata.normalize("NFKC", text).strip()
    if not folded.startswith("|"):
        # A bullet or sentence keys on its first word (`- D9 (re-read …): …` and `- D9: …` are
        # the same note), not on everything before the first colon (2026-10-26 review).
        match = re.match(r"[-*#\s]*([A-Za-z0-9_.][A-Za-z0-9_.-]*)", folded)
        return match.group(1).lower() if match else ""
    for token in folded.split("|"):
        cleaned = token.strip().strip("-*# ").lower()
        if cleaned:
            return cleaned
    return ""


def shape_key(text):
    """row_key plus the line's SHAPE: a table row and a bullet that share an id never pair
    (2026-10-26 review: an edited note paired with a removed table row and hid its removal)."""
    key = row_key(text)
    if not key:
        return ""
    return ("row:" if text.strip().startswith("|") else "line:") + key


def lowering(before_text, after_text):
    """How `after_text` lowers `before_text` (same-key constraints lines), or None.

    Cell by cell for table rows (2026-10-26 review): compared as one flat list of numbers, a
    row read the same when its criterion was reworded around the old number, when a lower
    number was appended in a later cell, or when a criterion lost its number. A prose line is
    one cell, where a number that no longer appears anywhere is the one that was dropped."""
    b_cells, a_cells = cells(before_text), cells(after_text)
    if len(b_cells) == 1 and len(a_cells) == 1:
        b_units, a_units = numbers_with_units(b_cells[0]), numbers_with_units(a_cells[0])
        before, after = [v for v, _ in b_units], [v for v, _ in a_units]
        gone = [(v, u) for v, u in b_units if v not in after]
        fresh = [(v, u) for v, u in a_units if v not in before]
        if not gone:
            return None
        if not fresh:
            return f"{gone[0][0]:g} -> (no number)"
        # The numbers that moved, paired in order when the counts agree (a line that restates
        # two values); a raise is a tightening and reads as one (PR #707 review).
        if len(fresh) == len(gone):
            for (old, _), (new, _) in zip(gone, fresh, strict=True):
                if new < old:
                    return f"{old:g} -> {new:g}"
            return None
        # Otherwise a vanished value is matched to the new values written with its unit, or to
        # every new value when none is: an unrelated higher number beside a lowered floor
        # (`80%` -> `70% … (100 cases)`) no longer reads as its replacement (#707 review).
        for old, unit in gone:
            candidates = [new for new, u in fresh if u == unit] or [new for new, _ in fresh]
            lower = [new for new in candidates if new < old]
            if lower:
                return f"{old:g} -> {max(lower):g}"
        return None
    for i, bcell in enumerate(b_cells):
        acell = a_cells[i] if i < len(a_cells) else ""
        before, after = numbers(bcell), numbers(acell)
        for j, value in enumerate(before):
            if j >= len(after):
                return f"{value:g} -> (no number)"
            if after[j] < value:
                return f"{value:g} -> {after[j]:g}"
        if before and _COMPARATOR.search(bcell) and _COMPARATOR.search(acell) and not _COMPARATOR_NUMERIC.search(acell):
            return "criterion no longer compares against a number"
        if len(after) > len(before) and _FLOOR_WORDS.search(acell):
            return f"a floor-shaped number was added: {after[len(before)]:g}"
    for acell in a_cells[len(b_cells):]:
        if numbers(acell) and _FLOOR_WORDS.search(acell):
            return f"a floor-shaped number was added: {numbers(acell)[0]:g}"
    return None


def scan(added, removed, constraints_name, repo):
    """Return findings as dicts: rule, path, line, detail (never matched text)."""
    findings = []

    def flag(rule, path, line, detail):
        findings.append({"rule": rule, "path": path or "(unknown)", "line": line, "detail": detail})

    def file_has_exceptions_heading(path):
        # A bullet added under a PRE-EXISTING ## Exceptions heading carries no heading line in
        # the diff, so the in-diff marker alone cleared it (#382). The on-disk file is the other
        # half of the evidence.
        try:
            text = (repo / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return False
        return any(EXCEPTIONS_HEADING.match(ln) for ln in text.splitlines())

    def media(path):
        return Path(path or "").suffix.lower() in BINARY_MEDIA

    in_exceptions = {}
    for path, line, text in added:
        if is_constraints(path, constraints_name) and EXCEPTIONS_HEADING.match(text):
            in_exceptions[path] = True
        surface = guard_surface_hit(path, text)
        if surface:
            flag("guard-surface", path, line, surface)
        if media(path):
            continue
        for name, pat in SUPPRESSIONS:
            if pat.search(text):
                flag("silenced-checker", path, line, name)
                break
        for name, pat in SKIPS:
            if pat.search(text):
                flag("test-made-easier", path, line, name)
                break
        for name, pat in STUBS:
            if pat.search(text):
                flag("unfinished-work", path, line, name)
                break
        if is_constraints(path, constraints_name):
            if EXCEPTION_ROW.match(text):
                flag("new-exception", path, line, "exception-row")
            elif text.strip().startswith(("-", "*")) and (
                    in_exceptions.get(path) or file_has_exceptions_heading(path)):
                flag("new-exception", path, line, "exceptions-bullet")

    gone = {}

    def deleted(path):
        if path not in gone:
            gone[path] = (git(repo, "cat-file", "-e", f"HEAD:{path}") is None
                          and not (repo / path).exists())
        return gone[path]

    in_deleted_files = {}
    for path, line, text in removed:
        surface = guard_surface_hit(path, text)
        if surface:
            flag("guard-surface", path, line, surface)
        if media(path) or not TEST_PATH.search(path or ""):
            continue
        if not ASSERTIONS.search(text):
            continue
        # A wholly deleted test FILE is a different move (and a visible one);
        # this rule is about a file that stayed and lost an assertion. A file that
        # moved stayed: _charge_moved_assertions decides which deletions are moves.
        if deleted(path):
            in_deleted_files.setdefault(path, []).append((line, text))
            continue
        flag("assertion-removed", path, line, "assertion")
    added = [row for row in added if not media(row[0])]
    removed = [row for row in removed if not media(row[0])]
    _charge_moved_assertions(in_deleted_files, added, removed, flag)
    _flag_undiscoverable_renames(added, removed, flag)
    _flag_lowered_rows(added, removed, constraints_name, flag, repo)
    return findings


def _lines_by_path(rows):
    out = {}
    for path, _line, text in rows:
        out.setdefault(path, []).append(text)
    return out


def _substantive(lines):
    return Counter(t.strip() for t in lines
                   if len(t.strip()) >= SUBSTANTIVE_LEN and any(c.isalnum() for c in t))


def _charge_moved_assertions(in_deleted_files, added, removed, flag):
    """Charge a moved test file's dropped assertions to where it went (2026-10-23 review, P2-6).

    Rename detection is off (collect_diff), so `git mv tests/a.py tests/b.py` plus one deleted
    assertion is a whole-file delete and a whole-file add -- and the deleted-file exemption
    waved the dropped assertion through. A deleted test file whose substantive lines mostly
    (MOVE_SIMILARITY, git's own -M default) reappear in the diff's added lines was moved, or
    split: every assertion it carried that is not re-added in a test path is flagged at the
    destination holding most of its lines -- the path a waiver for it would name. Fewer than
    half its lines surviving is the visible delete-plus-new-file this rule leaves to review."""
    if not in_deleted_files:
        return
    added_by_path = _lines_by_path(added)
    removed_by_path = _lines_by_path(removed)
    kept = Counter(t.strip() for p, _n, t in added if TEST_PATH.search(p or ""))
    for path, dropped in in_deleted_files.items():
        old = _substantive(removed_by_path.get(path, []))
        total = sum(old.values())
        if not total:
            continue
        everywhere, best, best_shared = Counter(), None, 0
        for other, lines in added_by_path.items():
            if other == path:
                continue
            new = _substantive(lines)
            everywhere.update(new)
            shared = sum((old & new).values())
            if shared > best_shared:
                best, best_shared = other, shared
        if best is None or sum((old & everywhere).values()) < MOVE_SIMILARITY * total:
            continue
        for line, text in dropped:
            if kept[text.strip()] > 0:
                kept[text.strip()] -= 1
                continue
            flag("assertion-removed", best, line, f"dropped moving from {path}:{line}")


def _flag_undiscoverable_renames(added, removed, flag):
    """A test def renamed so its runner no longer finds it (2026-10-23 review, section 5).

    `def test_x` removed and `def _test_x` (or `disabled_test_x`, Go's `TestX` -> `testX`)
    added in the same test file is a skip with no skip marker: the body is kept and never runs.
    The discovery prefix is the removed name's own (`test`/`Test`, case-sensitive); a new name
    that keeps it is still discovered, and a name that is re-added is a move, not a rename."""
    removed_defs = {}
    for path, line, text in removed:
        match = TEST_DEF.match(text)
        if match and TEST_PATH.search(path or "") and match.group(1).startswith(DISCOVERY_PREFIXES):
            removed_defs.setdefault(path, []).append(match.group(1))
    if not removed_defs:
        return
    added_defs = {}
    for path, line, text in added:
        match = TEST_DEF.match(text)
        if match and path in removed_defs:
            added_defs.setdefault(path, []).append((match.group(1), line))
    for path, names in removed_defs.items():
        new = added_defs.get(path, [])
        still_defined = {name for name, _line in new}
        for name in names:
            if name in still_defined:
                continue
            for other, line in new:
                if (other != name and other.lower().endswith(name.lower())
                        and not other.startswith(name[:4])):
                    flag("test-made-easier", path, line, "renamed-out-of-discovery")
                    break


def _flag_lowered_rows(added, removed, constraints_name, flag, repo=None):
    """threshold-lowered: a numbered constraints row must come back no lower (P2-5).

    Rows pair in order within their key (`row_key`), path by path. The in-place edit was the
    only shape this rule used to see: deleting the row, re-keying it (`D1` -> `D1b`) or
    replacing its number with a word left no same-key partner with a smaller number, so it
    read as silence (2026-10-23 review, P2-5). Now a numbered row with no partner is
    `row removed or re-keyed`, and a partner with fewer numbers is the number dropped. A row
    ADDED with no predecessor is a new floor: silent, like every tightening."""
    partners = {}
    for path, _line, text in added:
        if is_constraints(path, constraints_name):
            partners.setdefault((path, shape_key(text)), []).append(text)
    for path, line, text in removed:
        if not is_constraints(path, constraints_name):
            continue
        key, before = shape_key(text), numbers(text)
        if not key or not before:
            continue
        pool = partners.get((path, key))
        if not pool:
            flag("threshold-lowered", path, line, "row removed or re-keyed")
            continue
        detail = lowering(text, pool.pop(0))
        if detail:
            flag("threshold-lowered", path, line, detail)
    # A SECOND numbered row for a key the file already carries (2026-10-26 review): the old row
    # stays, a duplicate at a lower number is added, and a reader takes either for the floor. Read
    # off the final file for every added row, an edited twin included: a wording edit to the
    # original beside the appended duplicate used to hide the duplicate (PR #707 review).
    for path, line, text in added:
        key = shape_key(text)
        if not (is_constraints(path, constraints_name) and key.startswith("row:") and numbers(text)):
            continue
        others = [t for t in _file_rows(repo, path) if shape_key(t) == key]
        if len(others) > 1:
            flag("threshold-lowered", path, line, f"duplicate row for {key[4:]}")


def _file_rows(repo, path):
    """The table rows of `path` as it stands in the tree under review ([] when unreadable)."""
    if repo is None:
        return []
    try:
        text = Path(repo, path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln for ln in text.splitlines() if ln.strip().startswith("|")]


def load_waivers(path):
    """A waiver line names a rule id and a path. Missing file = no waivers (that
    is a clean state, not a could-not-run); an unreadable one IS a 2.

    A FILE reader, for callers holding a ledger of their own. main() never uses it: the
    guard reads the base ref's ledger (load_base_waivers), not the tree under review."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        return [ln for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    except OSError as err:
        raise GuardError(f"waiver file {path} is unreadable: {err}") from err


def read_at(repo, ref, rel):
    """The text of repository path `rel` at `ref`, or None when `ref` does not carry it.

    A path the ref carries but git cannot read is a could-not-run, never "no waivers"."""
    if git(repo, "cat-file", "-e", f"{ref}:{rel}") is None:
        return None
    text = git(repo, "cat-file", "blob", f"{ref}:{rel}")
    if text is None:
        raise GuardError(f"{ref}:{rel} exists but could not be read")
    return text


def waiver_rel(repo, waivers):
    """--waivers as a repository path. Waivers are read at the base ref (P1-7), so a ledger
    outside the repository has no base-ref version to read: a could-not-run, not a bypass."""
    p = Path(waivers)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(Path(repo).resolve())
        except ValueError as err:
            raise GuardError(f"--waivers {waivers} is outside the repository; waivers are read "
                             "at the base ref, so they must name a repository path") from err
    return p.as_posix()


def load_base_waivers(repo, ref, rel):
    """Waiver lines from the BASE ref's ledger (2026-10-23 review, P1-7).

    The ledger used to be read from the checked-out tree, so a change carrying a bar-lowering
    edit could carry its own `allow` beside it and print `clean (1 waived)`. At the base ref
    the change cannot have written it: a waiver lands on the base branch first, through the
    review that branch requires. A ledger the ref does not carry is no waivers."""
    text = read_at(repo, ref, rel)
    return [] if text is None else [ln for ln in text.splitlines() if ln.strip()]


def base_grant_pubkey(repo, ref, decisions):
    """The human-grant pubkey pinned AT THE BASE REF, or None when the ref pins none.

    Read from the same ref as the ledger: a key the change commits for itself would sign its
    own waivers. A malformed pin is a could-not-run (decisions.py's rule), never a pass."""
    rel = decisions.GRANT_PUBKEY_REL.as_posix()
    text = read_at(repo, ref, rel)
    if text is None:
        return None
    try:
        return decisions.parse_grant_pubkey(text, f"{ref}:{rel}")
    except decisions.DecisionsError as err:
        raise GuardError(str(err)) from err


# A waiver's IDENTITY, so the ledger can retire it: `floor-waiver:<rule>:<path-or-glob>`. Sharing
# one id across every waiver left them with nothing to supersede — a later `superseded` row names
# no particular waiver, so an `allow` stayed live forever (PR #308 review, P1). With scope in the
# id, decisions.active() does the retiring, which is the mechanism the ledger already has.
_WAIVER_ID_PREFIX = "floor-waiver:"
# The answers that GRANT. A DECISIONS record is a decision, and `deny` is one of the things it can
# say — reading the line as a bag of tokens made a record REFUSING a waiver grant it (PR #308
# review, P1). Anything not in this set, `deny` and `superseded` included, grants nothing.
_WAIVER_GRANTS = frozenset({"allow"})


def _load_decisions():
    """decisions.py, the sibling that owns the DECISIONS record format."""
    spec = importlib.util.spec_from_file_location(
        "decisions", Path(__file__).resolve().parent / "decisions.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _path_waived_by(token, path):
    """True when `token` names `path` exactly, or is a `dir/**` glob whose segments prefix it.

    Segment-wise, never substring: `src/new.pyc` must not cover `src/new.py`, and `src` must not
    cover `srcinternal/x`. A bare `**` is a blanket, not a waiver — it names nothing, so a reviewer
    reading the line learns nothing about the blast radius."""
    if token == path:
        return True
    if not token.endswith("/**"):
        return False
    prefix = [p for p in token[:-3].split("/") if p]
    if not prefix:
        return False
    return path.split("/")[:len(prefix)] == prefix


def _waiver_records(waivers, decisions, grant_pub, verified_only=True):
    """The waiver-id records that still stand: decisions.standing() first (a one-way line that is
    not a verified human grant is not a decision, so it neither out-ranks nor retires one), then
    decisions.active() (newest per id, `superseded` retired). verified_only=False skips the
    standing() filter -- for naming the line a reader expected to grant, never for granting."""
    records = []
    for line in waivers:
        record = decisions.parse_line(line)
        if record is not None and record["id"].strip().startswith(_WAIVER_ID_PREFIX):
            records.append(record)
    if verified_only:
        records = decisions.standing(records, grant_pub)
    return decisions.active(records)


def _scoped_allows(finding, records):
    """The standing `allow` records whose id scope covers this finding's rule and path."""
    for record in records:
        if record["answer"].strip().lower() not in _WAIVER_GRANTS:
            continue
        rule, _sep, scope = record["id"].strip()[len(_WAIVER_ID_PREFIX):].partition(":")
        if rule == finding["rule"] and _path_waived_by(scope, finding["path"]):
            yield record


def refused_waivers(finding, waivers, decisions, grant_pub=None):
    """[(raw, why)]: standing `allow` waivers for this finding that are not one-way human grants.

    Turning the old `taste`/`mechanical` waivers off is the point of #621, and a silent turn-off
    reads as a red build with no reason (the PR #308 lesson): name the line and what it lacks."""
    if decisions is None or not finding.get("path"):
        return []
    newest = _waiver_records(waivers, decisions, grant_pub, verified_only=False)
    return [(record["raw"], "; ".join(problems))
            for record in _scoped_allows(finding, newest)
            for problems in [decisions.grant_problems(record, grant_pub)] if problems]


def is_waived(finding, waivers, decisions=None, grant_pub=None):
    """A waiver is a DECISIONS RECORD that grants one, identified by the scope it covers.

    Four rounds of this, each fixing the previous one's blind spot, so the shape is worth stating
    plainly. `rule in line and path in line` let a superstring stand in for either field and let a
    sentence that merely mentioned both grant a waiver (#313). Requiring a `floor-waiver` token
    fixed the mention and not the meaning: a structured record with that ID and answer `deny` still
    granted, because the line was still read as a bag of tokens. Checking each record's own answer
    fixed that and left the ledger out: an `allow` retired by a later `superseded` kept granting,
    because every waiver shared one id and so had no identity to retire (PR #308 review, P1).

    So the waiver's scope lives in its ID — `floor-waiver:<rule>:<path-or-glob>` — and
    decisions.active() decides which records still stand: newest per id, `superseded` retired. No
    prose is parsed at all. The rule matches exactly, the path exactly or by an explicit `dir/**`
    glob. A decisions.py that will not load waives nothing.

    Round five (2026-10-23 review, P1-7): the standing `allow` must also BE a one-way human
    grant -- class `one-way`, a human source, and a verifying signature when `grant_pub` (the
    base ref's pinned key) is set: decisions.grant_problems, the check `decisions.py check`
    runs. Any `taste` or `mechanical` allow grants nothing, and the caller reads `waivers` from
    the base ref, so the change under review cannot supply one."""
    path = finding.get("path")
    if not path:
        return False
    if decisions is None:
        try:
            decisions = _load_decisions()
        except Exception:  # noqa: BLE001 - an unloadable sibling must not start granting waivers
            return False
    for record in _scoped_allows(finding, _waiver_records(waivers, decisions, grant_pub)):
        if not decisions.grant_problems(record, grant_pub):
            return True
    return False


def malformed_waivers(waivers):
    """[(raw, why)] for records that LOOK like waivers but cannot grant one.

    A format change turns waivers off silently, and the operator sees a red build with no reason
    (PR #308 review, P1). This does not honour the old shape — scope-in-prose is the matching the
    #313 findings removed as unsound, and reinstating it as a fallback would restore the hole where
    a line saying "we will NOT waive X" grants X. It says so instead, which is the migration path:
    the guard names the line it could not use and prints the id to write."""
    try:
        decisions = _load_decisions()
    except Exception:  # noqa: BLE001
        return []
    notes = []
    for line in waivers:
        record = decisions.parse_line(line)
        if record is None:
            continue
        ident = record["id"].strip()
        if ident == "floor-waiver":
            notes.append((record["raw"], "its scope is not in the id — waivers carry it there now, "
                                         "so the ledger can retire one without retiring all of them"))
        elif ident.startswith(_WAIVER_ID_PREFIX):
            rule, sep, scope = ident[len(_WAIVER_ID_PREFIX):].partition(":")
            if not (rule and sep and scope):
                notes.append((record["raw"], "its id is not `floor-waiver:<rule>:<path-or-glob>`"))
    return notes


def build_parser():
    p = argparse.ArgumentParser(
        prog="floor_guard.py",
        description="Diff-scoped detection of the six moves that lower the bar.",
        epilog="exit 0 clean / 1 findings / 2 could-not-run (never let a 2 read as a 0)",
    )
    p.add_argument("--base", default=None, help="base ref (default: origin/HEAD, then origin/main, origin/master, main, master)")
    p.add_argument("--constraints", default="CONSTRAINTS.md", help="constraints file whose numbers may not go down")
    p.add_argument("--waivers", default="docs/DECISIONS.md",
                   help="DECISIONS log path, read AT THE BASE REF; a one-way human "
                        "`floor-waiver:<rule>:<path>` allow waives that finding")
    p.add_argument("--repo", default=".", help="repository to guard (default: cwd)")
    p.add_argument("--quiet", action="store_true", help="print findings only, no clean banner")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        repo = repo_root(args.repo)
        base, shown = resolve_base(repo, args.base)  # a commit id; `shown` names it for people
        mb = merge_base(repo, base)
        added, removed = parse_diff(collect_diff(repo, mb))
        findings = scan(added, removed, args.constraints, repo)
        # The BASE ref's ledger, never the tree under review (2026-10-23 review, P1-7).
        waivers = load_base_waivers(repo, base, waiver_rel(repo, args.waivers))
    except GuardError as err:
        print(f"floor-guard: could not run: {err}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    for raw, why in malformed_waivers(waivers):
        print(f"floor-guard: NOT a usable waiver — {why}:\n  {raw.strip()[:200]}\n"
              "  write the id as `floor-waiver:<rule>:<path>` (or `:<dir>/**`), class `one-way`, "
              "answer `allow`",
              file=sys.stderr)

    try:
        _decisions = _load_decisions()  # once per run, not once per finding (#382)
    except Exception:  # noqa: BLE001 - an unloadable sibling waives nothing
        _decisions = None
    try:
        grant_pub = base_grant_pubkey(repo, base, _decisions) if _decisions else None
    except GuardError as err:
        print(f"floor-guard: could not run: {err}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    live = [f for f in findings if not is_waived(f, waivers, _decisions, grant_pub)]
    if not live:
        if not args.quiet:
            waived = len(findings)
            note = f" ({waived} waived)" if waived else ""
            print(f"floor-guard: clean{note}")
        return EXIT_CLEAN
    print(f"floor-guard: {len(live)} floor violation(s):", file=sys.stderr)
    for f in live:
        print(f"  [{f['rule']}] {f['path']}:{f['line']} ({f['detail']})", file=sys.stderr)
        for raw, why in refused_waivers(f, waivers, _decisions, grant_pub):
            print(f"      waiver at {shown} not honoured — {why}:\n        {raw.strip()[:200]}",
                  file=sys.stderr)
    print(
        f"\nEach lowers the bar. Fix the code, or land a waiver on {shown} FIRST: a DECISIONS "
        "record whose id is `floor-waiver:<rule>:<path>` (or `:<dir>/**`), class `one-way`, "
        "answer `allow`, appended with `decisions.py append --source human:<name>` (plus "
        "`--grant-sig` when .orca/human-grant-pubkey is pinned). Waivers are read at the base "
        "ref; one this change writes for itself is not.",
        file=sys.stderr,
    )
    return EXIT_FINDINGS


if __name__ == "__main__":
    sys.exit(main())
