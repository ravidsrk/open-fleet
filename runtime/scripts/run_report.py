#!/usr/bin/env python3
"""Bind a proof-tier advance to artifacts instead of a filename (issue #259).

Before this, `proof: self-run` in a mission's frontmatter needed only a file
under ``docs/runs/`` whose name and body mentioned the mission. A three-line
report with the right filename passed `scripts/validate.py`, `proof_status.py
--check`, and the whole suite — which made "the honesty is machine-checked"
false for the one claim it was written to protect.

What a tier advance has to survive here instead:

* a single ``RUN:`` header line whose fields parse;
* ``mission=`` matching the mission that claims the tier, and ``tier=`` matching
  the tier it claims — so a report cannot be re-pointed at another mission;
* ``inventory_at=`` resolving to a real commit **in this repository**;
* ``manifest=`` existing at that commit — the evidence manifest the run was
  graded against, not a path invented afterwards;
* ``verifier=`` recording the verifier's outcome, with the body carrying the
  ``verify.py`` invocation it came from (a RED is a legitimate recorded outcome:
  a solo run cannot manufacture an independent approver, and saying so is the
  point of the field);
* ``waves=`` (a mutating mission's report) written once, recording the number of
  dispatch waves the run ran; its WIP-curve section's table carries one complete row
  per wave 1..n (attention-budget.md's WIP-curve protocol, #365/#389/#387);
* the run-close integrity inventory re-deriving **at that commit**: at least one
  path verified and zero mismatched.

The inventory is the load-bearing half. Hashing at the recorded commit is what a
fabricated report cannot fake — the bytes have to have existed at a commit that
exists, and the working tree moving on afterwards (which it always does) neither
weakens nor breaks the check. The graded manifest must itself be one of the hashed
paths, and none of this run's OWN artifacts may be absent there: pinning a
neighbouring file while the document the verdict rests on floats free would bind
nothing that matters.

What a tier COSTS, since #286: an actual command execution. The graded manifest's
own ``commands[]`` ledger must carry a record of `verify.py` running against that
manifest, with a ``cmd_sha256`` that hashes its own command line and a ``wtree``
that resolves to a real object here. Prose is free -- a fabricated report cleared
the earlier gate in fifteen minutes by writing a command line -- so the body's
invocation is no longer the only evidence a run happened.

What closes the "could not have been typed" gap (#281/#386): a **signed verifier
transcript**. Once the coordinator's public key is committed at ``.orca/dispatch-pubkey``,
the ledger entry alone no longer suffices: the ``RUN:`` header must name
``transcript=<path>`` inside the run's own directory, and that file — read at the pin —
must be the ``{record, sig_b64}`` envelope ``verify.py --transcript-out --transcript-key``
(or ``dispatch-sign.py sign-transcript``) emits, verifying against that key, over the
graded manifest's exact bytes, with an exit code that agrees with ``verifier=`` and a
signed argument tuple that agrees with the invocation the body shows.

The same key closes the inventory's own gap (#386): the run-close integrity inventory
is worker-written text too, so once the key is committed its ENTRY SET must carry the
coordinator's signature (``inventory.py sign``, the same ``{record, sig_b64}`` envelope on
one HTML-comment line inside the block), verified here over exactly the entries the
report lists. Unsigned with the key present, or signed with no key to check it, refuses.

WHERE the key is read is the switch itself, so it is ancestry-aware (PR #489 round-1
review, BOT-2). The **grading base** is the default branch's current tip at verification
time (``origin/HEAD``, then ``origin/main``…, ``--base`` to name it). A pin that is an
ancestor of the grading base reads the key AT the pin: a report pinned before the key
landed keeps the unsigned path unchanged — the grandfather lane, and the ONLY way into
it. A pin OFF that ancestry — a branch forked from any pre-key commit, a dangling commit
— is judged against the key at the grading base: fresh artifacts on such a fork prove
nothing about the key, so "its own artifacts must exist there" was never a defence.

What this does NOT do, said plainly: it does not re-run `verify.py` and re-derive
the verdict. Without a committed key the ledger above is still written ON the
worker, so the floor it raises is "ran a command and recorded it against real
content", not "could not have been typed". That run's authorities are not reproducible after the fact — the
coordinator's out-of-band contract, a GitHub review lookup, the live worktree — so
a "re-derivation" here would be a different, weaker check wearing the same name.
What is checked is that the recorded outcome is attributable to a real invocation
and that every artifact behind it still hashes true at the recorded commit.

A report whose artifacts were never retained in this repository cannot pass, and
that is the intended answer, not a gap: it stays in ``docs/runs/`` as recorded
history while the mission's frontmatter says ``doctrine-only``. History and a
machine-checkable claim are different things.

Exit codes
    0  every checked report binds
    1  at least one report does not
    2  could not run (no skills/, unreadable input)
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil

import subprocess
import sys
from pathlib import Path

# h409 hygiene: one git resolution rule across the toolchain —
# resolved once, never a bare PATH lookup per call (reaudit-r2 P3).
GIT = shutil.which("git")


_GIT_ABSENT = "/nonexistent/git"


def _git_cmd(*args):
    """Argv head for every git call: the git resolved once at import — never a bare name that
    would re-resolve against a later PATH (Greptile #498). With no git on PATH the head is a
    fixed nonexistent absolute path, so the failure arrives at EXEC as FileNotFoundError: the
    exact OSError shape the callers' handlers are written for (git-less operation proceeds
    where documented, e.g. dispatch-sign's out-of-repo probe)."""
    return [GIT if GIT is not None else _GIT_ABSENT, *args]

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUNS_DIR = ROOT / "docs" / "runs"

_spec = importlib.util.spec_from_file_location("inventory", HERE / "inventory.py")
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)
# The transcript's canonical form and the Ed25519 verifier come from the signer itself — one
# scheme, one envelope, the same key files as the dispatch record (#281/#386).
_ds_spec = importlib.util.spec_from_file_location("dispatch_sign", HERE / "dispatch-sign.py")
dispatch_sign = importlib.util.module_from_spec(_ds_spec)
_ds_spec.loader.exec_module(dispatch_sign)

# Committing the coordinator's public key here is THE enforcement switch — for the signed
# dispatch record (verify-gate.sh discovers it) and, read at a report's own pin, for the signed
# verifier transcript below.
PUBKEY_PIN = ".orca/dispatch-pubkey"

RUN_HEADER_RE = re.compile(r"^RUN:\s*(.+?)\s*$", re.M)


def _invocation_re(manifest):
    r"""`verify.py … --manifest <THIS report's manifest>` — the transcript, not the word.

    Two tightenings, both learned the hard way. "the body contains 'verify.py'" was
    satisfied by any prose mentioning it. Replacing that with `--manifest \S+` was
    then satisfied by this very module's explanatory prose, which writes
    `verify.py … --manifest <path>` — `<path>` is a perfectly good `\S+`. So the
    argument has to be the actual manifest the RUN: header names: a sentence about
    verification cannot accidentally contain it, and a run that really happened has
    it for free.
    """
    return re.compile(r"verify\.py[^\n]*--manifest\s+" + re.escape(manifest) + r"(\s|$)")
FIELD_RE = re.compile(r"([a-z_]+)=(\S+)")
REQUIRED_FIELDS = ("mission", "tier", "inventory_at", "manifest", "verifier")
VERIFIER_OUTCOMES = {"GREEN", "RED"}
# Tiers a RUN: header may DECLARE. `doctrine-only` is legal here and advances nothing: it is how a
# report says "this run happened and is recorded, and it supports no tier claim". Without it a
# demoted report had to keep asserting the tier its own Evidence-binding section retracted, and
# nothing checked the contradiction — check_report only runs for missions claiming a tier ABOVE
# doctrine-only, so the stale header was unreachable (PR #308 review).
TIERS = {"doctrine-only", "self-run", "external-run"}
# ...but only these two are a tier ADVANCE that needs evidence behind it.
ADVANCING_TIERS = {"self-run", "external-run"}


def parse_run_header(text):
    """({field: value}, error). Exactly one RUN: line, every required field present."""
    headers = RUN_HEADER_RE.findall(text)
    if not headers:
        return None, (
            "no 'RUN:' header — a tier advance needs one line naming the mission, the "
            "tier, the commit its inventory was computed at, its manifest, and the "
            "verifier outcome"
        )
    if len(headers) > 1:
        return None, f"{len(headers)} 'RUN:' headers — exactly one is the report's identity"
    fields = dict(FIELD_RE.findall(headers[0]))
    missing = [f for f in REQUIRED_FIELDS if not fields.get(f)]
    if missing:
        return None, f"RUN: header is missing {missing} (want {list(REQUIRED_FIELDS)})"
    return fields, None


SHALLOW_REMEDY = "git fetch --unshallow"


def is_shallow(root):
    """True when ``root`` is a shallow clone: its history is truncated, so a run report's
    ``inventory_at=`` pin can be a real commit this clone simply does not have."""
    try:
        proc = subprocess.run(
            _git_cmd("rev-parse", "--is-shallow-repository"),
            cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except OSError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def path_exists_at(rev, path_text, root):
    return subprocess.run(
        _git_cmd("cat-file", "-e", f"{rev}:{path_text}"),
        cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# THE verifier, by path — not by basename. `/tmp/verify.py` is a script the worker wrote
# (PR #308 review); only this repository's own verifier counts.
VERIFIER_PATH_PARTS = ("runtime", "scripts", "verify.py")


def _is_repo_verifier(token, root):
    """True when `token` names THIS repository's verify.py."""
    path = Path(token)
    parts = tuple(part for part in path.parts if part != ".")
    if ".." in parts:
        return False  # an escape hatch out of the repo, wherever it currently points
    if tuple(parts[-3:]) != VERIFIER_PATH_PARTS:
        return False  # includes a bare `verify.py`, which resolves against cwd or PATH
    try:
        root = Path(root).resolve()
        return (root / path).resolve() == root.joinpath(*VERIFIER_PATH_PARTS)
    except (ValueError, OSError, RuntimeError):
        return False


_PYTHON_NAME_RE = re.compile(r"python(?:\d+(?:\.\d+)?)?t?", re.ASCII)
# World-writable and shared. No toolchain installs an interpreter under them, so anything wearing
# an interpreter's name there was put there by the run. Resolution matters: Path.is_relative_to is
# lexical, and on macOS /tmp and /var/tmp are symlinks into /private — the UNRESOLVED spelling of
# the same world-writable file escaped the refusal until both sides were resolved (#349).
def _scratch_roots():
    roots = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    tmpdir = os.environ.get("TMPDIR")  # tempfile tooling lands here; also run-writable
    if tmpdir:
        roots.append(Path(tmpdir))
    return tuple(root.resolve() for root in roots)


def _is_python_interpreter(token, root):
    """True when `token` names a Python interpreter the run did not supply itself.

    A basename test accepting anything that STARTS WITH `python` was the whole check, so
    `/tmp/python3` passed — an arbitrary executable, or a symlink to /bin/true, under a name the
    worker chose. The record then satisfied verifier_ran with neither an interpreter nor this
    repository's verifier having run at all (PR #327 review, P1).

    What a recorded string can establish is bounded, and it is the same bound the ledger itself
    carries: this refuses the forms the run controls, it does not authenticate the binary. A bare
    name is the documented form and resolves through PATH; a path is read only where a worker is
    not expected to be able to place a file. Authenticating the interpreter needs the
    coordinator-signed transcript of #281, not a longer pattern here.
    """
    path = Path(token)
    if not _PYTHON_NAME_RE.fullmatch(path.name):
        return False   # `python-decoy` and `pythonish` are not interpreters
    if "/" not in token:
        return True    # a bare name: PATH resolves it, exactly as the protocols document
    # A slash is what makes the shell open a FILE instead of searching PATH, so `./python3` is a
    # worker-placed file however much it reads like the bare name Path() would flatten it to.
    if not path.is_absolute() or ".." in path.parts:
        return False   # resolves against a cwd this check cannot know, or climbs out of one
    try:
        repo = Path(root).resolve()
        resolved = path.resolve()  # non-strict: resolves a symlinked prefix even for absent files
    except (ValueError, OSError, RuntimeError):
        return False
    if resolved.is_relative_to(repo):
        return False   # the tree under review is the one place the run certainly writes
    return not any(resolved.is_relative_to(scratch) for scratch in _scratch_roots())


def _valid_python_xoption(option):
    """Known CPython 3.13 startup value constraints (using/cmdline.html#cmdoption-X).

    This is argv validation, not authentication of the executable or its environment. In
    particular gil=0 needs a free-threaded build; future/build-specific options are not modeled.
    CPython permits arbitrary additional keys in sys._xoptions, so they are preserved.
    """
    name, sep, value = option.partition("=")
    if name == "utf8":
        return not sep or value in {"0", "1"}
    if name == "gil":  # introduced in 3.13; build availability is a separate concern
        return value in {"0", "1"}
    if name == "frozen_modules":
        return value in {"", "on", "off"}
    if name not in {"int_max_str_digits", "cpu_count", "tracemalloc"}:
        return True
    if not sep:
        return name == "tracemalloc"
    if name == "cpu_count" and value == "default":  # introduced in 3.13
        return True
    # initconfig.c uses wcstol plus an INT_MAX bound, not Python's int grammar (underscores).
    if value and not re.fullmatch(r"[ \t\r\n\f\v]*[+-]?[0-9]+", value):
        return False
    try:
        number = int(value or "0")
    except ValueError:
        return False
    if not 0 <= number <= 2147483647:
        return False
    if name == "int_max_str_digits":
        return number == 0 or number >= 640
    if name == "cpu_count":
        return number >= 1
    return number <= 65535  # tracemalloc's maximum traceback depth


def _python_script_index(argv, i):
    """Locate a script after Python options; reject non-script modes and unknown syntax.

    Short options can cluster; -W/-X consume the rest of their token or the NEXT token.
    Skipping all dash-prefixed tokens admits -cpass, -uV and --help without running a script.
    """
    xoptions = {}
    while i < len(argv) and argv[i].startswith("-"):
        token = argv[i]
        if token == "--":
            i += 1
            break
        if token == "--check-hash-based-pycs":
            if i + 1 >= len(argv) or argv[i + 1] not in {"always", "default", "never"}:
                return len(argv)
            i += 2
            continue
        if token == "-" or token.startswith("--"):
            return len(argv)
        for offset, flag in enumerate(token[1:], start=1):
            if flag in "WX":
                value = token[offset + 1:]
                if offset == len(token) - 1:
                    i += 1  # consume the separate option argument, never mistake it for a script
                    if i >= len(argv):
                        return len(argv)
                    value = argv[i]
                if flag == "X":
                    # CPython initializes from the FIRST occurrence of a key, not the last.
                    xoptions.setdefault(value.partition("=")[0], value)
                break
            if flag not in "bBdEiIOPqRsSuvx":
                return len(argv)  # includes c/m modes and h/?/V exits, even inside clusters
        i += 1
    return i if all(_valid_python_xoption(value) for value in xoptions.values()) else len(argv)


class _SilentParser(argparse.ArgumentParser):
    """argparse that raises instead of printing usage and calling sys.exit."""

    def error(self, message):
        raise ValueError(message)

    def exit(self, status=0, message=None):
        raise ValueError(message or f"exit {status}")


def _parsed_manifest(rest):
    """The `--manifest` value argparse would see in `rest`, or None if it would refuse the line.

    Hand-reading this argv diverged from argparse three times in review, three different ways: the
    first occurrence was taken where argparse keeps the last, and a dangling trailing `--manifest`
    read as the earlier value where argparse rejects the whole command line. The lesson is not "be
    more careful with the next hand-rolled scan" — it is that the only reliable model of a parser
    is that parser. So the recorded argv is PARSED, not scanned.

    `parse_known_args` because a recorded command legitimately carries flags this function does not
    model (--contract-source, --lighting, --execute-nc): an unrecognised flag is no reason to
    disbelieve the run, while a malformed one is.
    """
    parser = _SilentParser(add_help=False)
    parser.add_argument("--manifest")
    try:
        known, _unknown = parser.parse_known_args(list(rest))
    except (ValueError, SystemExit):
        return None
    return known.manifest


def executes_verifier(cmd, manifest_path, root=None):
    r"""True when `cmd` RUNS this repo's verify.py against `manifest_path` — parsed as argv.

    A regex over the command line is the wrong instrument here, and this module already has the
    scar tissue to prove it: `_invocation_re` was tightened twice, first because "the body
    contains verify.py" matched any prose, then because `--manifest \S+` matched this module's own
    docstring. Applied to a ledger RECORD it failed again — `echo verify.py --manifest <m>` hashes
    true, names a real tree, and invokes nothing. The regex is still right for the report BODY,
    which is prose; a recorded command is argv and is read as argv.

    Three further evasions review found in the argv reading itself, all fixed here. A basename test
    accepted `/tmp/verify.py`, a script the worker wrote; the path must be this repository's own
    verifier. Taking the FIRST `--manifest` disagreed with argparse, which takes the LAST — so
    `--manifest <graded> --manifest other.json` read as graded here while the real verifier read
    the other file. And the INTERPRETER went unread the same way `verify.py` once did: any
    executable whose name began with `python` was one, so `/tmp/python3` — a symlink to /bin/true
    — ran nothing and recorded a pass (PR #327 review, P1). See `_is_python_interpreter`.
    """
    if not isinstance(cmd, str):
        return False
    try:
        argv = shlex.split(cmd, comments=True)
    except ValueError:
        return False
    i = 0
    while i < len(argv) and (argv[i] == "env" or _ENV_ASSIGN_RE.match(argv[i])):
        i += 1
    if i >= len(argv):
        return False
    if _is_python_interpreter(argv[i], root or ROOT):
        i = _python_script_index(argv, i + 1)
        if i >= len(argv):
            return False
    if not _is_repo_verifier(argv[i], root or ROOT):
        return False
    return _parsed_manifest(argv[i + 1:]) == manifest_path


def blob_at(rev, path_text, root):
    """The bytes of `path_text` as of `rev`, or None. Reading the manifest AT the pinned commit,
    never from the working tree, is the whole point: the tree has moved on since the run."""
    proc = subprocess.run(
        _git_cmd("show", f"{rev}:{path_text}"),
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    return proc.stdout if proc.returncode == 0 else None


# git's empty tree, SHA-1 and SHA-256 object formats: always resolvable, never anyone's content.
EMPTY_TREES = frozenset({"4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                         "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"})


def tree_of(rev, root):
    """`rev`'s tree sha, or None."""
    proc = subprocess.run(
        _git_cmd("rev-parse", f"{rev}^{{tree}}"),
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    out = proc.stdout.strip()
    return out if proc.returncode == 0 and out else None


def verifier_ran(manifest_path, rev, root):
    """Errors that stop this report proving the verifier was RUN. [] means a run is recorded.

    Until #286 the only evidence a tier had that `verify.py` ever executed was PROSE: the report
    body had to contain a command line naming its own manifest. Prose is free. A fabricated
    `map-it` self-run — seven files, 32 lines, one commit — cleared the whole gate in under fifteen
    minutes because writing a command line costs nothing.

    So the tier now costs a command EXECUTION: the graded manifest's own `commands[]` ledger must
    carry a record of the verifier running, with a `wtree` that resolves to a real tree object
    in this repository. `evidence-run.py` writes those records; a hand-written one has to name a
    tree that really exists here and hash its own command line.

    Said plainly, because it bounds what this buys: the ledger is still written on the worker, so
    this raises the floor from "wrote a sentence" to "ran a command and recorded it against real
    content". The leg the worker cannot type is signed_transcript() below — a coordinator-signed
    verifier transcript checked against a committed key (#281) — and it is dormant until that key
    is committed.
    """
    raw = blob_at(rev, manifest_path, root)
    if raw is None:
        return [f"the graded manifest {manifest_path} cannot be read at {rev}"]
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        return [f"the graded manifest {manifest_path} at {rev} is not readable JSON ({err})"]
    if not isinstance(manifest, dict):
        return [f"the graded manifest {manifest_path} at {rev} is not a JSON object"]

    records = [c for c in (manifest.get("commands") or []) if isinstance(c, dict)]
    verifier = [c for c in records if executes_verifier(c.get("cmd"), manifest_path, root)]
    if not verifier:
        seen = ", ".join(repr(c.get("cmd")) for c in records) or "nothing"
        return [f"the graded manifest {manifest_path} records no commands[] entry running "
                f"verify.py against itself — a tier costs a RUN, not a sentence about one. Wrap the "
                f"verifier in evidence-run.py so the ledger carries it (#286). Recorded there: {seen}"]

    # Every candidate must bind to content, or the record describes nothing. The bound is
    # tree-shaped existence in THIS repo: evidence-run records DURING the run, before the
    # closing commit exists, so equality with the pinned commit's tree would refuse every real
    # run — but a blob or an unresolvable object binds to nothing (#382).
    problems = []
    for rec in verifier:
        line = rec["cmd"]
        digest, wtree = rec.get("cmd_sha256"), rec.get("wtree")
        actual = hashlib.sha256(line.encode("utf-8")).hexdigest()
        if digest != actual:
            problems.append(f"its cmd_sha256 {digest} does not hash its own command line ({actual})")
            continue
        if not (isinstance(wtree, str) and wtree):
            problems.append("it carries no wtree, so it is bound to no content at all")
            continue
        tree = tree_of(wtree, root)
        if tree is None:
            problems.append(f"its wtree {wtree[:12]}… does not resolve to a tree object in this "
                            "repository")
            continue
        if tree in EMPTY_TREES:
            # git knows the empty tree in EVERY repository without storing it, so naming it
            # passed "resolves to a real tree" while binding the record to no content at all
            # (2026-10-23 review, P3). A verifier run is made on a checkout with files in it.
            problems.append(f"its wtree {wtree[:12]}… is git's built-in EMPTY tree, which "
                            "resolves in any repository and binds the record to no content")
            continue
        return []  # one sound record is enough
    return [f"the graded manifest {manifest_path} records a verify.py run that binds to nothing: "
            + "; ".join(problems)]


# verify.py's argument tuple as the transcript signs it (verify.py _Transcript.ARGS): the flag each
# key came from, so the invocation the report body SHOWS can be parsed into the same shape and
# compared. Two are switches; the rest take a value and are None when unset.
SIGNED_ARGS = ("contract_source", "contract_digest", "repo", "base", "symbol", "execute_nc",
               "unit_class", "no_gh", "lighting", "lane", "dispatch_record", "dispatch_pubkey",
               "nc_command", "git_dir", "evidence_root", "provenance", "retention_pubkey")
_SWITCH_ARGS = ("execute_nc", "no_gh")
# h409 F-5: the verifier TOOLCHAIN a signed transcript names — verify.py and every sibling it
# loads by path (verify.py _Transcript.TOOLCHAIN mirrors this). The transcript hashes each file;
# the binding below checks every hash against the file at the graded pin, so a transcript proves
# WHICH verifier ran (a substituted sibling fails to bind) — the verifier's identity, nothing more.
TOOLCHAIN_FILES = ("verify.py", "_verify_sig.py", "diff_scope.py", "ed25519.py", "dispatch-sign.py",
                   "inventory.py", "gitexec.py")


def invocation_args(text, manifest):
    """The parsed argument tuple of every `verify.py … --manifest <manifest>` line the body shows,
    in SIGNED_ARGS shape. A line that does not parse as argv is not an invocation."""
    out = []
    for line in text.splitlines():
        if not _invocation_re(manifest).search(line):
            continue
        try:
            argv = shlex.split(line, comments=True)
        except ValueError:
            continue
        start = next((i + 1 for i, tok in enumerate(argv) if tok.endswith("verify.py")), None)
        if start is None:
            continue
        parser = _SilentParser(add_help=False)
        for key in SIGNED_ARGS:
            flag = "--" + key.replace("_", "-")
            if key in _SWITCH_ARGS:
                parser.add_argument(flag, dest=key, action="store_true")
            else:
                parser.add_argument(flag, dest=key, default=None)
        try:
            known, _unknown = parser.parse_known_args(argv[start:])
        except (ValueError, SystemExit):
            continue
        out.append(vars(known))
    return out


# The grading base: the default branch's current tip, resolved the way floor_guard/diff_scope do.
# HEAD is the last resort — the checkout run_report is running in — never a header field.
GRADING_BASES = ("origin/HEAD", "origin/main", "origin/master", "main", "master", "HEAD")


def grading_base(root, base=None):
    """The commit the unsigned lane is proven against: `base` if named, else the first of
    GRADING_BASES that resolves. None only in a repository with no commit at all."""
    for candidate in ((base,) if base else GRADING_BASES):
        proc = subprocess.run(
            _git_cmd("rev-parse", "--verify", "-q", f"{candidate}^{{commit}}"),
            cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    return None


def is_ancestor(rev, base, root):
    """`rev` reachable from `base` (a commit is its own ancestor)."""
    return subprocess.run(
        _git_cmd("merge-base", "--is-ancestor", rev, base),
        cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def key_rev(rev, root, base=None):
    """(commit the enforcement switch is read at, why). The pin when it sits on the grading base's
    ancestry — that is the grandfather lane's one door; the grading base when it does not."""
    tip = grading_base(root, base)
    if tip is None:
        return None, "no grading base resolves (tried " + ", ".join(GRADING_BASES) + ")"
    if base is None and blob_at(rev, PUBKEY_PIN, root) is not None and not any(
            subprocess.run(_git_cmd("rev-parse", "--verify", "-q", f"{c}^{{commit}}"),
                           cwd=str(root), stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL).returncode == 0
            for c in GRADING_BASES[:-1]):
        # h409 O-3.3: only HEAD resolves, and the pin carries a key — reading the key at the
        # grading base would read it where the pin chooses (the pin IS HEAD). Refusing the
        # self-pinned fallback; an origin/main (or any named base) re-opens the lane.
        return None, ("only HEAD resolves as a grading base and the pin carries a key — the pin "
                      "would choose its own judge; refusing the self-pinned fallback (h409 O-3.3)")
    if is_ancestor(rev, tip, root):
        return rev, f"the pin, an ancestor of the grading base {tip[:12]}"
    return tip, (f"the grading base {tip[:12]} — the pin {rev[:12]} is not an ancestor of it, so the "
                 "key is read where the pin cannot choose")


def enforcement_key(rev, root, base=None):
    """(32 pubkey bytes or None, commit it was read at, why) — THE switch, resolved AND parsed
    once for every signed leg (transcript, inventory) so none of them can disagree about whether
    enforcement is on or re-state the malformed-pin refusal. `at` is None when the switch cannot
    be read at all — no grading base resolves, or the committed pin is not a 32-byte hex key;
    `why` is then the refusal itself, fail-closed."""
    at, why = key_rev(rev, root, base)
    if at is None:
        return None, None, f"{why} — the unsigned lane needs an ancestry proof, so the claim fails closed"
    pin = blob_at(at, PUBKEY_PIN, root)
    # No fallback to the pin's own key when the grading base carries none: a
    # claim commit that introduces its own pubkey off the base would then
    # verify its own signed legs against a key it chose (full-review forge).
    # With no key at the switch, the signed legs fail closed on any claimed
    # envelope and the unsigned grandfather lane is the only lane left.
    if pin is None:
        return None, at, why
    try:
        pub = bytes.fromhex(pin.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError) as err:
        return None, None, f"{PUBKEY_PIN} at {at} is malformed ({err}) — fail-closed"
    if len(pub) != 32:
        return None, None, f"{PUBKEY_PIN} at {at} is malformed (not a 32-byte hex key) — fail-closed"
    return pub, at, why


def signed_inventory(lines, entries, rev, root, base=None):
    """Errors that stop this report proving its run-close inventory was SIGNED by the coordinator
    (#386, U-SIG-2). [] means either no key is committed where the switch is read and no envelope
    is present, or the envelope verifies against that key over exactly the entry set the report
    lists. The inventory is read from the report as check_report reads it (the document itself, not
    a blob at the pin — the report is written after the pin it names); the key is read at
    enforcement_key(), the same place the transcript rule reads it. Absence never binds: an
    envelope with no key to verify it, and no envelope with a key present, both refuse."""
    pub, at, why = enforcement_key(rev, root, base)
    if at is None:
        return [why]
    try:
        _idx, envelope = inventory.find_signature(lines)
    except inventory.InventoryError as err:
        return [f"integrity inventory {inventory.SIGNATURE_TAG}: {err}"]
    if pub is None and envelope is None:
        return []
    if pub is None:
        return [f"integrity inventory carries an {inventory.SIGNATURE_TAG} but no {PUBKEY_PIN} is "
                f"committed at {at} — nothing can verify it, so the claim fails closed (#386)"]
    if envelope is None:
        return [f"{PUBKEY_PIN} is committed at {at} ({why}), so an UNSIGNED integrity inventory no "
                "longer binds — sign its entry set with `inventory.py sign --key <coordinator seed>` "
                "(#386)"]
    try:
        signed = inventory.verify_signature(envelope, entries, pub)
    except inventory.SignatureRefused as problem:
        return [f"integrity inventory signature does not bind: {problem} (key: {PUBKEY_PIN} at {at})"]
    if signed != inventory.inventory_digest(entries):  # bound means the key said so over THIS set
        return [f"integrity inventory signature does not bind: the verifier returned {signed!r}, not "
                f"this inventory's digest (key: {PUBKEY_PIN} at {at})"]
    return []


def signed_transcript(fields, rev, run_dir, root, base=None, text=""):
    """Errors that stop this report proving its verdict was SIGNED by the coordinator (#281/#386).
    [] means either no key is committed where the switch is read and none is claimed, or the named
    transcript verifies against that key and binds to this report's claims.

    The transcript and the manifest are read AT `rev`, like everything else here. The KEY is read
    at key_rev(): the pin when the pin is on the grading base's ancestry (a report pinned before
    the key landed keeps the unsigned path), the grading base itself when it is not (a fork from a
    pre-key commit is judged by the key the base carries, not by the key it chose to fork before).
    Absence never binds: a missing signature with the key present, a missing key with a signature
    present, and a manifest digest that is None on either side all refuse."""
    pub, at, why = enforcement_key(rev, root, base)
    if at is None:
        return [why]
    transcript = fields.get("transcript")
    if pub is None and transcript is None:
        return []
    if pub is None:
        return [f"RUN: transcript={transcript} is named but no {PUBKEY_PIN} is committed at {at} "
                "— nothing can verify it, so the claim fails closed (#281)"]
    if transcript is None:
        return [f"{PUBKEY_PIN} is committed at {at} ({why}), so a ledger entry alone no longer proves "
                "the verifier ran — the RUN: header must name transcript=<path>, the coordinator-"
                "signed verdict envelope (verify.py --transcript-out/--transcript-key, or "
                "dispatch-sign.py sign-transcript) (#281)"]
    if run_dir is not None and not transcript.startswith(run_dir + "/"):
        return [f"RUN: transcript={transcript} is outside this run's own directory {run_dir}/ — a "
                "run is graded on its own verdict, not another run's"]
    raw = blob_at(rev, transcript, root)
    if raw is None:
        return [f"RUN: transcript={transcript} cannot be read at {rev}"]
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        return [f"RUN: transcript={transcript} at {rev} is not readable JSON ({err})"]
    if not (isinstance(envelope, dict) and isinstance(envelope.get("record"), dict)
            and isinstance(envelope.get("sig_b64"), str)):
        return [f"RUN: transcript={transcript} is an UNSIGNED verdict (no record/sig_b64 envelope) "
                f"and {PUBKEY_PIN} is committed at {at} — rejected; sign it with the coordinator's "
                "seed (#281)"]
    try:
        sig = base64.b64decode(envelope["sig_b64"], validate=True)
    except ValueError as err:
        return [f"RUN: transcript={transcript} sig_b64 is malformed ({err}) — fail-closed"]
    record = envelope["record"]
    if not dispatch_sign._load_ed25519().checkvalid(
            sig, dispatch_sign.canonical_transcript(record), pub):
        return [f"RUN: transcript={transcript} signature INVALID for the {PUBKEY_PIN} committed at "
                f"{at} — not the coordinator's verdict (forged, tampered, or another key) (#281)"]
    # Bind the signed verdict to THIS report's claims: the manifest it names and its exact bytes at
    # the pin, the outcome the header records, and the argument tuple the body's invocation shows.
    # None on either side is an absence, and an absence binds nothing (round-1 R-2).
    problems = []
    manifest = fields["manifest"]
    if record.get("manifest") != manifest:
        problems.append(f"it judges manifest {record.get('manifest')!r}, not {manifest}")
    graded = blob_at(rev, manifest, root)
    if graded is None:
        problems.append(f"the graded manifest {manifest} cannot be read at {rev}, so there are no "
                        "bytes to bind")
    elif record.get("manifest_sha256") is None:
        problems.append("it signs no manifest_sha256 — a verdict over unknown bytes")
    elif record.get("manifest_sha256") != hashlib.sha256(graded).hexdigest():
        problems.append(f"its manifest_sha256 {str(record.get('manifest_sha256'))[:12]}… is not the "
                        f"graded manifest's bytes at {rev} "
                        f"({hashlib.sha256(graded).hexdigest()[:12]}…)")
    want = 0 if fields["verifier"] == "GREEN" else 2
    if record.get("exit") != want:
        problems.append(f"its exit {record.get('exit')!r} disagrees with RUN: verifier="
                        f"{fields['verifier']} (expected exit {want})")
    # The args are signed so they can be READ (BOT-1): the verdict is a verdict under a policy,
    # and the policy must be the one the report shows and the one the mission's class demands.
    signed = record.get("args")
    if not (isinstance(signed, dict) and signed):
        problems.append("it signs no argument tuple, so under which policy the verdict was "
                        "reached is unknown")
    else:
        missing = sorted(set(SIGNED_ARGS) - set(signed))
        unexpected = sorted(set(signed) - set(SIGNED_ARGS))
        if missing or unexpected:
            problems.append(f"its signed argument tuple is partial — missing keys {missing}"
                            + (f", unexpected keys {unexpected}" if unexpected else "")
                            + " — the full verifier policy tuple must be signed, not a subset "
                            "(a transcript may omit no control it was reached under)")
        else:
            shown = invocation_args(text, manifest)
            if not any(all(inv[k] == signed[k] for k in SIGNED_ARGS) for inv in shown):
                summary = " ".join(f"{k}={signed[k]!r}" for k in SIGNED_ARGS if signed[k] not in (None, False))
                problems.append(f"its signed argument tuple ({summary or 'every flag unset'}) matches no "
                                f"verify.py invocation the body shows — the verdict was reached under "
                                "a policy the report does not claim")
        mutation = _mutation_missions(root, rev)
        if mutation and fields["mission"] in mutation and signed.get("unit_class") != "mutation":
            problems.append(f"it was judged as unit_class={signed.get('unit_class')!r}, but "
                            f"{fields['mission']} is a mutation-class mission (evidence-manifest.md "
                            "§3) — a verdict on a lesser class proves nothing about this one")
    # The toolchain is signed so the VERIFIER can be identified (h409 F-5): every file verify.py
    # loads, hashed, must be the file at the graded pin. A set that is absent, partial, or names
    # other bytes is a verdict by an unknown verifier — a substituted sibling is exactly that.
    files = (record.get("toolchain") or {}).get("files") if isinstance(record.get("toolchain"), dict) else None
    if not isinstance(files, dict):
        problems.append("its toolchain names no file set (toolchain.files) — which verifier "
                        "reached the verdict is unknown; a verify_sha256 alone covers one of the "
                        f"{len(TOOLCHAIN_FILES)} files the verifier loads (h409 F-5)")
    else:
        for name in TOOLCHAIN_FILES:
            signed_sha = files.get(name)
            at_pin = blob_at(rev, f"runtime/scripts/{name}", root)
            if not isinstance(signed_sha, str):
                problems.append(f"its toolchain.files does not name runtime/scripts/{name}, a "
                                "module the verifier loads — a partial set binds no verifier identity")
            elif at_pin is None:
                problems.append(f"runtime/scripts/{name} cannot be read at {rev}, so the signed "
                                f"toolchain hash {signed_sha[:12]}… binds to no file at the pin")
            elif signed_sha != hashlib.sha256(at_pin).hexdigest():
                problems.append(f"its toolchain.files pins runtime/scripts/{name} at {signed_sha[:12]}…, "
                                f"not the file at {rev} ({hashlib.sha256(at_pin).hexdigest()[:12]}…) — "
                                "a different verifier (or a substituted sibling) reached this verdict")
    if problems:
        return [f"RUN: transcript={transcript} verifies but does not bind this report: "
                + "; ".join(problems)]
    return []


def _mutation_missions(root, rev=None):
    """The mutation-class mission set from evidence-manifest.md §3 — the one place the class list
    lives, so this check and the done-floor never enumerate different sets. Read at the report's
    pinned revision first (the policy in force for the run), then the working tree. None means the
    policy exists at neither — the repo predates the protocol, and the obligation is unscoped
    rather than violated."""
    for text in (_read_at_rev(rev, "runtime/evidence-manifest.md", root) if rev else None,
                 _read_worktree(root)):
        if text is None:
            continue
        m = re.search(r"\*\*Mutation units\*\* \(([^)]*)\)", text)
        if m:
            return {name.strip() for name in m.group(1).split(",")}
    return None


def _read_at_rev(rev, path_text, root):
    try:
        proc = subprocess.run(
            _git_cmd("cat-file", "blob", f"{rev}:{path_text}"),
            cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_worktree(root):
    try:
        return (Path(root) / "runtime" / "evidence-manifest.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# attention-budget.md's WIP-curve protocol, machine-checked (#365): every mutating run records one
# row per dispatch wave, or the ≥3-run graduation evidence base can silently never accumulate — "a
# cap recorded nowhere was never a cap". The row schema is the one the protocol's table names
# (#389 — "any row carrying builders=/reviewers=" bound a settings-only row): a table row whose
# cells carry wave=<k>, the WIP setting as builders=<n> reviewers=<n>, and a measured value for
# every metric. A row is a WIP-curve row when it names a wave; the settings alone are not a point.
WIP_ROW_KEYS = ("wave", "builders", "reviewers", "throughput", "latency_median", "latency_max",
                "rework", "freshness")
_WIP_CELL_RE = re.compile(r"(?<![\w=])([a-z_]+)=([^\s|`]*)")
_COUNT_RE = re.compile(r"\d+")
_MEASURED_RE = re.compile(r"\d\S*")  # a number, units free after it: 1.5/h, 12m, 1/4
_WIP_COUNTS = {"wave": "<k>", "builders": "<n>", "reviewers": "<n>"}  # integers; metrics are <v>
_WIP_ROW_SCHEMA = " ".join(f"{k}={_WIP_COUNTS.get(k, '<v>')}" for k in WIP_ROW_KEYS)
# Where the rows live (#387): the report's WIP-curve section — docs/runs/TEMPLATE.md's
# `## WIP-curve protocol row` heading — outside fenced code. Every pipe-prefixed line used to be
# read, so a complete row quoted in a fenced example or a deviations table bound as the run's
# evidence, or tripped the duplicate/stray-wave checks against the real rows. An ATX heading
# whose text begins `WIP-curve protocol row` as whole words (so not `... rows`) opens the section
# (any level; what follows varies by report) — one that merely begins by naming the WIP curve,
# such as another run's quoted example, does not (verdict r1); the next heading of any kind ends it.
WIP_SECTION = "## WIP-curve protocol row"
_WIP_SECTION_RE = re.compile(r" {0,3}#{1,6}[ \t]+WIP-curve[ \t]+protocol[ \t]+row\b")
_HEADING_RE = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
# A backtick fence's info string holds no backtick (CommonMark): '```text`example``' is prose with
# inline code, and read as a fence it swallowed the rows after it (PR #401 review).
_FENCE_RE = re.compile(r" {0,3}(`{3,}(?=[^`]*$)|~{3,})")
_SETEXT_RE = re.compile(r" {0,3}(?:=+|-+)[ \t]*$")
_BREAK_RE = re.compile(r" {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")
_QUOTE_RE = re.compile(r" {0,3}>")
_ITEM_RE = re.compile(r" {0,3}(?:[-+*]|(\d{1,9})[.)])(?=[ \t]|$)")
# A block quote's paragraph sits at a column no line reaches: its lines carry '>', so a line under
# it without one is never its underline (--- is a thematic break, === is more of its text).
_QUOTED = float("inf")


def _indent(line, start=0):
    """The number of spaces line[start:] opens with; a tab counts as none here. The tab rule is
    the caller's: _wip_section_lines expands each line to CommonMark's stops of 4 before it
    measures, so there '\tnote' is as deep as '    note' (verdict r5, r6 S6-1)."""
    rest = line[start:]
    return len(rest) - len(rest.lstrip(" "))


def _wip_section_lines(text):
    """The lines inside the report's WIP-curve section(s), fenced code excluded. A heading quoted
    inside a fence is code too, so it neither opens nor closes the section. A setext heading — a
    paragraph underlined with = or - in its own container — ends the section like any other
    (verdict r1). List items are followed by the column their content starts at (CommonMark), so
    a fence nested in one is still code, and a paragraph indented into one is still its own."""
    inside, fence, para, items, empty = False, None, None, [], False
    for raw in text.splitlines():
        line = raw.expandtabs(4)
        indent = _indent(line)
        if fence:
            # CommonMark: the closing fence is the same character, at least as long, bare, and
            # up to three spaces past the column of the list item holding the fence. A line left
            # of that column ends the item, and the fence with it, and is read (verdict r5 F-2).
            char, col = fence
            if line.strip() and indent < col:
                fence = None
            else:
                closer = _FENCE_RE.match(line, col)
                if (closer and closer.group(1)[0] == char[0] and len(closer.group(1)) >= len(char)
                        and not line[closer.end():].strip()):
                    fence = None
                continue
        if not line.strip():
            # An item begins with at most one blank line, so one still empty ends here (verdict r4).
            if empty:
                items.pop()
            para, empty = None, False
            continue
        # The list items this line is indented into, then any it opens. An item interrupts a
        # paragraph in its own container only with content, and an ordered one only from 1:
        # 'Deviations / 2. x / ---' is one paragraph underlined (PR #401 review).
        kept = len(items)
        while kept and items[kept - 1] > indent:
            kept -= 1
        base, opened = (items[kept - 1] if kept else 0), []
        while not _BREAK_RE.match(line, base):
            item = _ITEM_RE.match(line, base)
            rest = line[item.end():] if item else ""
            if not item or (not opened and para == base
                            and not (rest.strip() and int(item.group(1) or 1) == 1)):
                break
            gap = _indent(line, item.end())
            base = item.end() + (gap if rest.strip() and 0 < gap <= 4 else 1)
            opened.append(base)
        empty = bool(opened) and not line[base:].strip()
        opener = _FENCE_RE.match(line, base)
        heading = _HEADING_RE.match(line)
        setext = not opened and para is not None and indent >= para and _SETEXT_RE.match(line, para)
        if opener:
            fence = (opener.group(1), base)
        elif heading:
            inside = bool(_WIP_SECTION_RE.match(line))
        elif setext:
            inside = False
        elif inside:
            yield raw
        # Only a paragraph can be underlined, and only in its own container. After a table row, a
        # heading, a fence or a thematic break, --- is a thematic break or table syntax. Under a
        # list item's paragraph but left of its content, or under a block quote's, --- is a
        # thematic break and === is more of its text (PR #401 review). The section stays open.
        quote = _QUOTE_RE.match(line, base)
        if (opener or heading or setext or _BREAK_RE.match(line, base)
                or line.lstrip().startswith("|")):
            items[kept:], para = opened, None
        elif opened or para is None or quote:
            # Four columns past it is indented code, which nothing underlines (verdict r4), a tab
            # included (verdict r5).
            items[kept:] = opened
            para = (_QUOTED if quote else
                    base if line[base:].strip() and _indent(line, base) < 4 else None)
        # Otherwise the line continues the open paragraph, lazily or not, and closes nothing.


def _wip_rows(text):
    """(row, {key: value}, doubled keys) for every table row in the report's WIP-curve section
    that names a wave — its WIP-curve rows (#387). A key written twice is reported, never
    collapsed: dict() keeps the last value, so `throughput=TBD throughput=1` would bind on the 1
    (PR #391 review)."""
    rows = []
    for line in _wip_section_lines(text):
        if line.lstrip().startswith("|"):
            pairs = _WIP_CELL_RE.findall(line)
            keys = [k for k, _v in pairs]
            if "wave" in keys:
                doubled = sorted({k for k in keys if keys.count(k) > 1})
                rows.append((line.strip(), dict(pairs), doubled))
    return rows


def _wip_cell_ok(key, value):
    if value is None:
        return False
    pattern = _COUNT_RE if key in _WIP_COUNTS else _MEASURED_RE
    return bool(pattern.fullmatch(value))


def _wip_curve_errors(text, mission, root, report_path, rev=None):
    missions = _mutation_missions(root, rev)
    if missions is None:
        return []  # the protocol exists at neither the pinned rev nor the worktree — unscoped
    if mission not in missions:
        return []  # report-only and planning runs carry no dispatch waves
    rows = _wip_rows(text)
    if not rows:
        return [f"{report_path}: a mutating run records one WIP-curve row per dispatch wave, as a "
                f"table row carrying {_WIP_ROW_SCHEMA} under the report's `{WIP_SECTION}` heading, "
                "outside fenced code (docs/runs/TEMPLATE.md, attention-budget.md) — none found; "
                "a cap recorded nowhere was never a cap (#365, #387)"]
    errors = []
    for row, cells, doubled_keys in rows:
        if doubled_keys:
            errors.append(f"{report_path}: WIP-curve row {row!r} carries {doubled_keys} more than "
                          "once — one value per cell, or the row contradicts itself (#389)")
            continue
        missing = [k for k in WIP_ROW_KEYS if not _wip_cell_ok(k, cells.get(k))]
        if missing:
            errors.append(f"{report_path}: WIP-curve row {row!r} carries no measured {missing} — "
                          f"the protocol's row is {_WIP_ROW_SCHEMA} (attention-budget.md, #389)")
    # The recorded waves are 1..n of the RUN: header's waves=<n> — the report's own count of the
    # dispatch waves it ran. Without it one row can stand in for a whole multi-wave run (#389).
    # Read every waves=, never a dict: `waves=3 waves=1` would bind on the 1 (the F3 collapse).
    header = RUN_HEADER_RE.search(text)
    counts = [v for k, v in FIELD_RE.findall(header.group(1)) if k == "waves"] if header else []
    if len(counts) > 1:
        errors.append(f"{report_path}: RUN: header carries waves= more than once ({counts}) — one "
                      "count of the dispatch waves, or the header contradicts itself (#389)")
        return errors
    declared = counts[0] if counts else None
    if declared is None or not _COUNT_RE.fullmatch(declared) or int(declared) < 1:
        errors.append(f"{report_path}: RUN: waves={declared or '<missing>'} — a mutating run records "
                      "the number of dispatch waves it ran as waves=<n> (n ≥ 1); its WIP-curve rows "
                      "are checked against waves 1..n (attention-budget.md, #389)")
        return errors
    recorded = range(1, int(declared) + 1)
    named = [int(c["wave"]) for _row, c, _doubled in rows if _COUNT_RE.fullmatch(c["wave"])]
    absent = [k for k in recorded if k not in named]
    doubled = sorted({k for k in named if named.count(k) > 1})
    stray = sorted({k for k in named if k not in recorded})
    if absent:
        errors.append(f"{report_path}: RUN: waves={declared} but no WIP-curve row for wave(s) "
                      f"{absent} — one complete row per recorded wave (attention-budget.md, #389)")
    if doubled:
        errors.append(f"{report_path}: wave(s) {doubled} carry more than one WIP-curve row — "
                      "one row per wave, or the curve double-counts it (#389)")
    if stray:
        errors.append(f"{report_path}: WIP-curve row(s) for wave(s) {stray} outside the recorded "
                      f"waves 1..{declared} (RUN: waves={declared}) (#389)")
    return errors


def check_report(report_path, mission, tier, root=None, base=None):
    """Errors that stop `mission` claiming `tier` on this report. [] means bound. `base` names the
    grading base (default: the default branch's tip, see grading_base)."""
    root = root or ROOT
    report = Path(report_path)
    if not report.is_absolute():
        report = root / report
    errors = []
    if not report.is_file():
        return [f"proof_evidence {report_path} does not exist"]
    try:
        text = report.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        return [f"proof_evidence {report_path} is unreadable: {err}"]

    fields, err = parse_run_header(text)
    if err:
        return [f"{report_path}: {err}"]

    if fields["mission"] != mission:
        errors.append(
            f"{report_path}: RUN: mission={fields['mission']} but {mission} claims it "
            "— a run report belongs to the mission that ran"
        )
    if fields["tier"] != tier:
        errors.append(
            f"{report_path}: RUN: tier={fields['tier']} but the frontmatter claims {tier}"
        )
    if fields["verifier"] not in VERIFIER_OUTCOMES:
        errors.append(
            f"{report_path}: RUN: verifier={fields['verifier']} — want one of "
            f"{sorted(VERIFIER_OUTCOMES)} (a recorded RED is honest; an unrecorded one is not)"
        )
    elif not _invocation_re(fields["manifest"]).search(text):
        # "the body contains the string verify.py" was satisfied by any prose that
        # mentioned it (PR #277 review, P1). The body must show the actual command,
        # run against the manifest this report is graded on.
        errors.append(
            f"{report_path}: RUN: verifier={fields['verifier']} but the body shows no "
            f"verify.py invocation against {fields['manifest']} that the outcome could "
            "have come from — record the command and its exit code, not a description of them"
        )

    rev = fields["inventory_at"]
    if not inventory.rev_exists(rev, root):
        if is_shallow(root):
            # Still fatal: a pin this clone cannot resolve verifies nothing, and a tier claim
            # must not pass unchecked just because history was truncated. But the cause is the
            # clone, not the report — say so, and name the one command that fixes it.
            errors.append(
                f"{report_path}: RUN: inventory_at={rev} cannot be resolved because this is a "
                f"SHALLOW clone (git clone --depth …) — run `{SHALLOW_REMEDY}` in {root} and "
                "re-run; the pin is checked against full history, never skipped"
            )
        else:
            errors.append(
                f"{report_path}: RUN: inventory_at={rev} is not a commit in this repository "
                "— an unresolvable pin verifies nothing"
            )
        return errors

    manifest = fields["manifest"]
    if not path_exists_at(rev, manifest, root):
        errors.append(f"{report_path}: RUN: manifest={manifest} does not exist at {rev}")
    run_dir = run_directory(report, mission, root)
    if run_dir is None:
        errors.append(
            f"{report_path}: filename must be docs/runs/<YYYY-MM-DD>-{mission}-<tier>.md "
            "— the run directory is derived from it"
        )
    elif not manifest.startswith(run_dir + "/"):
        errors.append(
            f"{report_path}: RUN: manifest={manifest} is outside this run's own directory "
            f"{run_dir}/ — a run is graded against its own manifest, not another run's"
        )

    # #286: the tier must cost a command execution, not a sentence describing one.
    for problem in verifier_ran(manifest, rev, root):
        errors.append(f"{report_path}: {problem}")
    # #281: with the coordinator's key committed where the switch is read, it must be SIGNED.
    for problem in signed_transcript(fields, rev, run_dir, root, base, text):
        errors.append(f"{report_path}: {problem}")

    errors.extend(_wip_curve_errors(text, mission, root, report_path, rev=rev))

    try:
        _report, lines, entries = inventory.load(report)
    except inventory.InventoryError as exc:
        errors.append(f"{report_path}: integrity inventory: {exc}")
        return errors
    # #386: with the key committed where the switch is read, the entry set itself must be SIGNED.
    for problem in signed_inventory(lines, entries, rev, root, base):
        errors.append(f"{report_path}: {problem}")
    matched, mismatched, missing = inventory.check_entries(entries, report, root, at=rev)
    if mismatched:
        for path_text, recorded, actual in mismatched:
            errors.append(
                f"{report_path}: inventory {path_text} at {rev}: recorded {recorded[:12]}…, "
                f"actual {actual[:12]}…"
            )
    if not matched:
        errors.append(
            f"{report_path}: inventory verified nothing at {rev} "
            f"({len(missing)} listed path(s) absent there) — the tier is not artifact-bound"
        )
    elif run_dir is not None and not any(p.startswith(run_dir + "/") for p in matched):
        errors.append(
            f"{report_path}: no verified inventory path lives in this run's own directory "
            f"{run_dir}/ — borrowing another run's artifacts is not evidence of this one"
        )
    # The manifest the run was GRADED against has to be one of the hashed artifacts.
    # Without this, the inventory could hash one trivial file while the manifest — the
    # document the whole verdict rests on — went unpinned and could be edited freely
    # afterwards (PR #277 review, P1).
    if manifest not in matched:
        where = "hashes differently" if any(p == manifest for p, _r, _a in mismatched) else (
            "is not in the inventory at all" if manifest not in missing else
            "is listed but absent at that commit")
        errors.append(
            f"{report_path}: the graded manifest {manifest} {where} — the inventory must pin the "
            "document the verdict rests on, not only its neighbours"
        )
    # A run's own artifacts are the ones it is responsible for retaining. A path
    # elsewhere may legitimately have moved since (inventory.py treats MISSING as a
    # snapshot, not a mismatch); one inside this run's directory going absent means
    # the evidence was not kept.
    if run_dir is not None:
        gone = sorted(p for p in missing if p.startswith(run_dir + "/"))
        if gone:
            errors.append(
                f"{report_path}: this run's own artifact(s) {gone} are absent at {rev} — a run "
                "must retain the evidence it claims, even when other listed paths have moved on"
            )
    return errors


# Reports bound before a run's directory had to be named for its report. A closed list: a new
# report keeps its artifacts in a directory named for it, so no report can borrow another's.
LEGACY_RUN_DIRS = {"2026-09-14-clean-sweep-self-run": "2026-09-14-clean-sweep-tracker"}
# A report may carry its tier after its run's name: `…-ship-it-self-run.md` beside `…-selfrun/`.
TIER_SUFFIXES = ("self-run", "selfrun", "external-run")


def run_directory(report, mission, root=None):
    """`docs/runs/<date>-<mission>…` — the directory a run's own artifacts live in.

    Derived from the report filename, never from the RUN: header, so a report
    cannot nominate someone else's directory. The directory is the one named
    for the report: its exact stem, or the stem less a tier suffix (`self-run`
    also spelled `selfrun`), or the closed LEGACY_RUN_DIRS entry. Any other
    same-day directory naming the mission belongs to another run and is never
    lent (#694 review: `…-trajectories-602-live` took `…-602-adapters/`, and a
    report of any name took a mission's only same-day directory). With none of
    these present the report's own stem is returned, which fails closed.
    """
    m = re.match(r"^(\d{4}-\d{2}-\d{2})-", report.stem)
    if not m or mission not in report.stem:
        return None
    runs_dir = ((root or ROOT) / "docs" / "runs") if root is not None else RUNS_DIR
    stem = report.stem
    if stem in LEGACY_RUN_DIRS:
        return f"docs/runs/{LEGACY_RUN_DIRS[stem]}"
    names = [stem]
    for tier in TIER_SUFFIXES:
        if stem.endswith("-" + tier):
            base = stem[:-len(tier) - 1]
            names += [base, base + "-selfrun"] if tier == "self-run" else [base]
    mtoks = mission.split("-")
    for name in names:
        # Token-contiguous, never substring (#382, PR #387 review): "map-it" must not match
        # "map-iteration".
        tokens = name[len(m.group(1)) + 1:].split("-")
        if (runs_dir / name).is_dir() and any(tokens[i:i + len(mtoks)] == mtoks
                                               for i in range(len(tokens) - len(mtoks) + 1)):
            return f"docs/runs/{name}"
    return f"docs/runs/{stem}"


def _missions(root):
    """[(mission, tier, proof_evidence)] for every mission above doctrine-only."""
    spec = importlib.util.spec_from_file_location("proof_status", HERE / "proof_status.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = []
    for rec in mod.collect(root / "skills", root):
        if rec["proof"] in ADVANCING_TIERS:
            out.append((rec["name"] or rec["dir"], rec["proof"], rec["proof_evidence"]))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="run_report.py",
        description="Check that a proof-tier advance is bound to artifacts, not a filename.",
        epilog="exit 0 bound / 1 not bound / 2 could-not-run",
    )
    parser.add_argument("report", nargs="?", help="one report to check (default: every claim)")
    parser.add_argument("--mission", help="mission the report is claimed by (with `report`)")
    parser.add_argument("--tier", help="tier claimed (with `report`)")
    parser.add_argument("--base", default=None, metavar="REV",
                        help="the grading base the unsigned lane is proven against (default: "
                             "origin/HEAD, then origin/main, origin/master, main, master, HEAD)")
    args = parser.parse_args(argv)

    if args.report:
        if not (args.mission and args.tier):
            parser.error("--mission and --tier are required with an explicit report")
        claims = [(args.mission, args.tier, args.report)]
    else:
        if not (ROOT / "skills").is_dir():
            print(f"skills/ not found at {ROOT / 'skills'}", file=sys.stderr)
            return 2
        claims = _missions(ROOT)

    failed = False
    seen = {}
    for mission, tier, evidence in claims:
        if evidence and evidence in seen:
            print(
                f"FAIL {mission} ({tier}) — proof_evidence {evidence} is already claimed by "
                f"{seen[evidence]}; one run report proves one mission's tier"
            )
            failed = True
            continue
        if evidence:
            seen[evidence] = mission
        if not evidence:
            print(f"FAIL {mission} ({tier}) — no proof_evidence")
            failed = True
            continue
        errors = check_report(evidence, mission, tier, base=args.base)
        if errors:
            failed = True
            print(f"FAIL {mission} ({tier})")
            for error in errors:
                print(f"   - {error}")
        else:
            print(f"bound {mission} ({tier}) — {evidence}")
    if not claims:
        print("no mission claims a tier above doctrine-only")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
