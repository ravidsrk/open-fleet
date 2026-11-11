#!/usr/bin/env python3
"""verify.py — independent, separate-process re-derivation of an evidence manifest.

The completion oracle runs OUTSIDE the producing session and TRUSTS NOTHING IN THE WORKER'S MANIFEST
that it can instead check against authoritative state. The manifest is a *claim*; the authorities are:
  - the COORDINATOR's frozen contract — the criterion denominator materialized at dispatch and passed
    in as --contract-source/--contract-digest, NOT read from the worker's manifest;
  - GIT — commit existence and ancestry;
  - GITHUB — whether a review actually happened at the reviewed SHA (a manifest-set reviewed_sha
    proves nothing);
  - the NEGATIVE-CONTROL, EXECUTED (--execute-nc) in throwaway worktrees against the command the
    COORDINATOR names (--nc-command) — the artifact alone is corroboration, never proof, and a
    command the worker names proves only what the worker chose to prove (#279).

Checks (evidence-manifest.md section 2), scope FIRST:
  1. scope: re-derive the criterion set from the COORDINATOR-supplied authoritative contract
     (--contract-source read at --contract-digest) — never from the manifest. Confirm the manifest's
     criteria / criterion_ids cover it and that its own declared digest matches (swap detection).
     FAIL-CLOSED without an authoritative contract: a manifest cannot certify its own denominator.
  2. base_sha / head_sha are real commits (git cat-file -e).
  3. review: a mutation unit needs an INDEPENDENT APPROVED review whose commit == head_sha, looked
     up on GitHub (gh api). FAIL-CLOSED — a manifest-set reviewed_sha is not evidence a review happened.
     The two lanes that WAIVE that review (--lighting dark-eligible, --no-gh) pass ONLY with an
     EXECUTED negative control: there the control is the whole oracle, so it cannot be text (#256).
  4. negative control: structured (known tool, KILLED/RED verdict, pinned mutant, artifact) AND the
     artifact must corroborate. With --execute-nc the control is APPLIED in a throwaway worktree at
     head_sha and the command --nc-command names must go NON-ZERO under it and ZERO at clean
     head_sha (#255, #279).
  5. commands: a mutation unit needs ≥1 recorded exit-0 command whose `wtree` is head_sha's tree,
     written by evidence-run.py — the clean-env re-run as a machine check (#3 of the audit ledger).
  6. redaction: the manifest and every named artifact are scanned for credential shapes (#14).
  7. ancestry (best-effort) · 8. symbol-on-base (best-effort).
  9. intent packet (mutation units) · 10. lighting legality · 11. reviewer_mode legality ·
  12. Art-12/50 provenance presence (claims only) · 12b. the provenance retention receipt bound
  OFFLINE to its signed inventory and this manifest, when claimed (#608) · 13. signed dispatch
  provenance (#135) · 14. class downgrade measured against the actual diff (#310).

Every evidence path is repo-relative and bounded by the git toplevel; a manifest-named artifact is
PINNED — tracked at head_sha, or hashed in the manifest's `artifacts[]` inventory (#267); a tracked
path the inventory also hashes must match that hash at head_sha (#596).

Usage:
    verify.py --manifest <m.json> --contract-source <path@ref> --contract-digest <sha256:…>
              [--repo owner/name] [--unit-class mutation|report-only|planning]
              [--execute-nc --nc-command <cmd>] [--base <branch>] [--symbol <tok>]
              [--transcript-out <path> [--transcript-key <seed>]]
              [--retention-pubkey <path|path@ref>]
    # exit 0 = all REQUIRED checks pass · 2 = a REQUIRED invariant FAILED, or an argparse usage
    # error · 1 = a dependency or internal failure (verify-gate.sh blocks on any non-zero)
    # --transcript-out writes the verdict as a machine-readable object; with --transcript-key it
    # is the coordinator-SIGNED envelope run_report.py requires against .orca/dispatch-pubkey
    # (#281/#386). Without the pair, behaviour is unchanged: stdout + exit code. A requested
    # transcript that is not written (unwritable path; a seed asked to sign an absence) is
    # exit 1 on a green verdict — a RED keeps its 2.
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
import base64
import configparser
import fnmatch
import functools
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# The coordinator classifies each unit at dispatch (a --unit-class flag / ORCA_UNIT_CLASS), NEVER the
# worker's manifest. Mutation units land code and need the review + negative-control authorities;
# report-only / planning units bind evidence differently (evidence-manifest.md section 3). A missing
# or unknown class defaults to mutation (fail-safe): the strict authorities run.
UNIT_CLASSES = ("mutation", "report-only", "planning")
NC_TOOLS = {"mutmut", "cosmic-ray", "stryker", "pitest", "cargo-mutants", "go-mutesting", "revert",
            "hand"}  # hand = a hand-written mutant (boundary flip / negated condition / zeroed return, compile-preserving; the diff is quoted in the artifact)
REVIEWER_MODES = {"cross-vendor", "same-vendor-fresh", "instructed-isolation"}
LIGHTING_VALUES = {"lit", "dark-eligible"}
# The negative-control tools verify.py can REPLAY itself (#255, #750 C11): `revert` restores
# base_sha paths (or range-reverts), and `hand` plus the six mutation tools apply the unified diff
# quoted in negative_control.artifact. Any tool without a replayable control under --execute-nc is
# fail-closed: an unreplayable control is not an executed one.
EXECUTABLE_NC_TOOLS = ("revert", "hand", "mutmut", "cosmic-ray", "stryker", "pitest",
                       "cargo-mutants", "go-mutesting")
# Criterion ids in a frozen source: hyphenated (AC-1, SC-12, REQ-3) or compact (AC1, SC12). A JSON
# source may instead declare an explicit criterion_ids array, which is unambiguous and PREFERRED —
# write frozen contracts as JSON where you can.
# #268: in a TEXT source an id counts only where it BEGINS a list item or a line and is followed by
# a separator — `- AC-1: …`, `2. SC-3)`, `REQ-4.`. Prose tokens of the same shape (`SHA-256`,
# `PR-12`, `RFC-7519`, `ISO-8601`) are NOT criteria; counting them is a FALSE RED that makes the
# gate unusable on realistic contracts (docs/reviews/2026-09-10-review.md A11). The anchor is the one place a contract
# author declares a criterion, so under-counting (which would let scope shrink) stays unlikely.
CRIT_ID_RE = re.compile(
    r"(?m)^[ \t]*(?:[-*]|\d+\.)?[ \t]*((?:[A-Z][A-Z0-9]*-\d+)|(?:[A-Z]{2,}\d+))[ \t]*[:.)]")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
# #14: a SHA-pinned manifest is permanent, so a credential that reaches one is permanent too.
# gitleaks is preferred when installed; these shapes are the fail-closed built-in floor.
REDACTION_PATTERNS = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("inline-credential", re.compile(
        r"(?i)\b(?:password|passwd|secret)\s*=\s*[\"']?[^\s\"';,)}<]{6,}")),
)
# A run where NOTHING was killed (the pinned mutant among them) — the sound-fail signal. Aggregate
# survivor counts of OTHER mutants are NOT here: a multi-mutant run where the pinned mutant WAS killed
# is valid, so survival is scoped to the pinned mutant id in check_negative_control.
_NC_ZERO_KILL_RE = re.compile(
    r"(?i)(not\s+killed|not\s+red|\bno\s+mutants?\s+killed\b|killed\s*[:=]\s*0\b"
    r"|\b0(?:\.0+)?\s*%\s+killed\b|\b0\s+mutants?\s+killed\b|\b0\s+killed\b)")


def _run(args, timeout=20, cwd=None, env=None):
    """Run a command; return (code, stdout, stderr). Never raises. argv[0] is None when the
    pinned authority it names was absent at startup (h409 R2): that is an error here, never a
    reason to look the name up on PATH again. No leg reads stdin: an inherited one (a hook
    payload, a pipe nobody closes) would let a git hook or filter block the verifier (#629)."""
    if args[0] is None:
        return 1, "", _Authority.ABSENT_GIT
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                           cwd=cwd, env=env, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, OSError) as err:
        return 1, "", str(err)


def _run_bytes(args, timeout=20, env=None):
    """Run a command; return (code, stdout_bytes, stderr). stdout is RAW bytes — no newline
    translation (#180) — stderr stays text for error messages. Never raises."""
    if args[0] is None:
        return 1, b"", _Authority.ABSENT_GIT
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, check=False, env=env,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as err:
        return 1, b"", str(err)


# The TWO ROOTS a verification stands on (#442). A chained-run manifest lives in ONE repo and
# pins SHAs in ANOTHER: the chaining report sits in the fleet repo, the leg commits in the target
# repo. Every git leg used to run in the process cwd and every evidence path was bounded against
# THAT one toplevel, so a cross-repo manifest satisfied neither invocation and could be verified
# from nowhere. `git` is what --git-dir names (where the SHAs are); `evidence` is what
# --evidence-root names (what bounds the paths). Both are COORDINATOR state, written once from
# argv in main() — a manifest never names the root it is judged against — and while both are None
# every resolution below is the single-repo one, unchanged.
_ROOTS = {"git": None, "evidence": None}


def _git(args, timeout=10):
    code, out, _ = _run([_Authority.git_bin(), *(["-C", _ROOTS["git"]] if _ROOTS["git"] else []),
                         *args], timeout=timeout, env=_Authority.git_env())
    return code, out.strip()


def _git_bytes(args, timeout=20):
    """A git read whose stdout must stay RAW bytes (#180), against the SHA root (#442)."""
    return _run_bytes([_Authority.git_bin(), *(["-C", _ROOTS["git"]] if _ROOTS["git"] else []),
                       *args], timeout=timeout, env=_Authority.git_env())


def infer_repo():
    code, url = _git(["remote", "get-url", "origin"])
    if code != 0:
        return None
    m = re.search(r"[:/]([^/]+/[^/]+?)(?:\.git)?$", url.strip())
    return m.group(1) if m else None


class _EvidenceManifest(dict):
    """One verification's immutable evidence snapshot; never supplied by manifest JSON."""
    def __init__(self, data, raw, path=None):
        super().__init__(data)
        self.raw = raw
        self.path = path  # where these bytes were read (W3-04: a receipt binds a PATH, not a digest)
        self.artifact_bytes = {}


def load_manifest(path):
    try:
        raw = Path(path).read_bytes()
        obj = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as err:
        return None, f"unreadable/invalid manifest: {err}"
    if not isinstance(obj, dict):
        return None, f"manifest must be a JSON object, got {type(obj).__name__}"
    return _EvidenceManifest(obj, raw, path), None


def _toplevel():
    """The toplevel of the repo the SHAs live in — the --git-dir clone when one is named."""
    code, top = _git(["rev-parse", "--show-toplevel"])
    return top if code == 0 else None


def _evidence_toplevel():
    """The toplevel that BOUNDS evidence paths: --evidence-root when named, else the repo the
    verifier was RUN IN — derived WITHOUT the --git-dir prefix, so pointing the SHA legs at
    another clone never silently moves this bound (#442)."""
    top = _ROOTS["evidence"]
    if top is None:
        code, out, _ = _run([_Authority.git_bin(), "rev-parse", "--show-toplevel"],
                            env=_Authority.git_env())
        top = out.strip() if code == 0 else None
    return top


def _roots_are_split():
    """True when the SHAs and the evidence live in DIFFERENT repositories (#442).

    The tracked-at-head_sha shortcut in _read_artifact is a SINGLE-REPO identity: `the file I
    resolved IS the blob git tracks at that commit`. Across two roots that identity does not
    hold — the SHA repo may carry an unrelated file at the same relative path, and its bytes are
    commit-pinned to the WRONG repository. So the split is what decides whether the shortcut is
    even available; under a split, evidence passes only on its artifacts[] pin, read from the
    evidence root. Two clones of one project are two repositories here: same paths, different
    roots, so the pin still governs. Identity must be PROVEN — if either toplevel cannot be
    resolved we fail closed and treat the roots as split.

    Answered ONCE per (roots, cwd) and cached (review P3): it used to spawn two git processes
    per artifact read. The first answer is also the one taken before any executed control ran
    worker code, so a later filesystem move cannot flip it mid-run."""
    if _ROOTS["git"] is None and _ROOTS["evidence"] is None:
        return False
    key = (_ROOTS["git"], _ROOTS["evidence"], os.getcwd())
    if key not in _roots_are_split.cache:
        sha_top, ev_top = _toplevel(), _evidence_toplevel()
        if sha_top is None or ev_top is None:
            split = True
        else:
            try:
                split = Path(sha_top).resolve() != Path(ev_top).resolve()
            except OSError:
                split = True
        _roots_are_split.cache[key] = split
    return _roots_are_split.cache[key]


_roots_are_split.cache = {}  # (git root, evidence root, cwd) -> split; main() clears it per run


def _resolve(path):
    """Resolve a manifest-relative path against the evidence root. Returns (Path|None, err).

    #267: an ABSOLUTE path, or one that escapes the root, is REFUSED. Evidence outside the
    clone is evidence no auditor can re-derive — docs/reviews/2026-09-10-review.md A10 walked a negative-control artifact
    out to a temp dir, untracked and unhashed, and the gate read it happily. There is no permissive
    fallback: outside a git repo there is no toplevel to bound against, so the read fails closed
    rather than silently widening. --evidence-root moves WHICH root bounds the path (#442); it
    never relaxes the bound, and main() refuses a root that is not itself inside a clone."""
    # h409 F-3: pathlib drops `./` segments, so the containment check below already judges the
    # NORMALIZED spelling; the git lookups in read_source/_read_artifact must hand git the SAME
    # spelling (`<sha>:./x` is cwd-relative to git, `<sha>:x` is toplevel-relative) — they do, via
    # Path(path).as_posix() — or a verifier run below the toplevel binds a path absent at the root.
    p = Path(path)
    if p.is_absolute():
        return None, f"absolute evidence path refused — must be repo-relative (#267): {path}"
    bound = "the evidence root" if _ROOTS["evidence"] is not None else "the repo toplevel"
    if p.parts and p.parts[0] == "..":
        return None, f"evidence path escapes {bound} (#267): {path}"
    top = _evidence_toplevel()
    if top is None:
        return None, "not inside a git repo — no toplevel to bound the evidence path against (#267)"
    root = Path(top).resolve()
    try:
        full = (root / p).resolve()
    except OSError as err:  # pragma: no cover — resolve() rarely raises on POSIX
        return None, str(err)
    if full != root and root not in full.parents:
        return None, f"evidence path escapes {bound} (#267): {path}"
    return full, None


def read_source(source):
    """Read a source: `path@gitref` reads the immutable blob at a real commit; a bare path is read
    from the working tree, bounded by _resolve. Returns (raw_bytes, err). Bytes are NOT stripped or
    newline-translated — the digest must see exactly what `shasum -a 256` saw (#180)."""
    if not source:
        return None, "missing"
    path, sep, ref = source.partition("@")
    if sep and ref:
        if path.startswith("-") or ref.startswith("-"):
            return None, "refusing option-like ref/path (leading '-') — see git-option-injection guard"
        if Path(path).is_absolute():
            return None, f"absolute path refused in a path@ref source (#267): {path}"
        code, out, err = _git_bytes(["show", f"{ref}:{Path(path).as_posix()}"])  # F-3
        return (out, None) if code == 0 else (None, (err.strip() or "git ref not found"))
    resolved, err = _resolve(path)
    if err:
        return None, err
    try:
        return resolved.read_bytes(), None
    except OSError as oserr:
        return None, str(oserr)


def artifact_inventory(m):
    """The manifest's `artifacts[]` integrity inventory as {path: sha256-hex}. Entries may be bare
    strings (named, but NOT pinned) or `{"path": …, "sha256": …}` objects; only the latter pin a
    working-tree file."""
    out = {}
    for entry in (m.get("artifacts") or []):
        if isinstance(entry, dict):
            path, digest = entry.get("path"), entry.get("sha256")
            if isinstance(path, str) and isinstance(digest, str):
                out[path] = digest.strip().lower().replace("sha256:", "", 1)
    return out


def read_artifact(m, path):
    if isinstance(m, _EvidenceManifest):
        if path not in m.artifact_bytes:
            m.artifact_bytes[path] = _read_artifact(m, path)
        return m.artifact_bytes[path]
    return _read_artifact(m, path)


def _read_artifact(m, path):
    """Read a MANIFEST-NAMED artifact. Returns (raw_bytes, err).

    #267: two conditions, both required.
      1. the path is repo-relative and inside the toplevel (_resolve);
      2. the BYTES are pinned — either the path is TRACKED at `head_sha`
         (`git cat-file -e <head_sha>:<path>`; the blob at that commit is what gets read), or the
         working-tree file's sha256 matches an entry in the manifest's `artifacts[]` inventory.
    An untracked, unhashed file is a claim ABOUT a file, not evidence: it can be rewritten between
    the run and the audit and nothing notices. A tracked path the inventory ALSO pins must match
    that pin against the blob it reads (#596): a declared digest that binds no bytes is a false
    claim in a permanent record, and one taken over the overlay pins bytes nobody read."""
    if not path:
        return None, "missing"
    if "@" in path:
        return None, "artifact must be a repo-relative path, not a path@ref (#267)"
    resolved, err = _resolve(path)
    if err:
        return None, err
    head = m.get("head_sha")
    split = _roots_are_split()
    spelled = Path(path).as_posix()  # the spelling _resolve bounded, never the manifest's (F-3)
    typed = _git(["cat-file", "-t", f"{head}:{spelled}"]) if (not split and head
                                                              and HEX40_RE.match(str(head))) else (1, "")
    if typed[0] == 0 and typed[1] == "blob":  # a tracked DIRECTORY passes `cat-file -e`, and
        # `git show` would print its listing as if it were artifact bytes (reaudit-r2 P3)
        code, out, gerr = _git_bytes(["show", f"{head}:{spelled}"])
        if code != 0:
            return None, (gerr.strip() or "cannot read the tracked artifact at head_sha")
        pinned = artifact_inventory(m).get(path)  # tracked is pinned; a declared pin must agree
        blob = hashlib.sha256(out).hexdigest()
        if pinned and blob != pinned:
            return None, (f"artifact '{path}' is tracked at head_sha as {blob} but artifacts[] pins "
                          f"{pinned} — a declared pin must bind the blob the verifier reads (#596)")
        return out, None
    try:
        raw = resolved.read_bytes()
    except OSError as oserr:
        return None, str(oserr)
    want = artifact_inventory(m).get(path)
    if not want:
        why = ("is not pinned by a sha256 in the manifest's artifacts[] integrity inventory — "
               "under split roots the SHA repository is never consulted for evidence bytes (#442)"
               if split else
               "is neither tracked at head_sha nor pinned by a sha256 in the manifest's "
               "artifacts[] integrity inventory")
        return None, f"artifact '{path}' {why} — unpinned evidence (#267)"
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        return None, (f"artifact '{path}' hashes {got} but artifacts[] pins {want} — the evidence "
                      "changed after it was inventoried (#267)")
    return raw, None


def sha256_of(content):
    """Digest of RAW BYTES, matching `shasum -a 256` (coordinators compute digests over bytes)."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _norm_digest(d):
    return d if d.startswith("sha256:") else "sha256:" + d


# Any token SHAPED like a criterion id, wherever it sits. CRIT_ID_RE only matches the ones that
# BEGIN a list item or line, which is what keeps `see RFC-7519` out of the denominator (#268).
CRIT_SHAPED_RE = re.compile(r"\b((?:[A-Z][A-Z0-9]*-\d+)|(?:[A-Z]{2,}\d+))\b")


def _criterion_family(token):
    """The family prefix of a criterion id, in either supported shape: AC-1 -> AC, SC12 -> SC.

    Both shapes are counted by CRIT_ID_RE, so both need a family. Reading the family off the hyphen
    alone skipped every compact id, and A16 then worked verbatim by dropping one character: a
    contract counting `- SC12:` while hiding `| SC13 |` in a table row was not flagged, though the
    hyphenated spelling of the same attack was (PR #308 review, P1).
    """
    head, sep, _ = token.rpartition("-")
    return head if sep else token.rstrip("0123456789")


def hidden_criterion_ids(content, counted):
    """Criterion ids the contract carries in a form the extractor does not count (A16; #296).

    The denominator is the whole scope guarantee: coverage is measured against it, so a contract
    that hides criteria from the extractor shrinks the thing the unit is graded on while still
    reading as a full specification to a human. Attack A16 wrote them as table rows and em-dash
    lines — `| AC-2 | … |`, `AC-3 — …` — and a three-criterion contract graded as one.

    Refusing every uncounted `AAA-9` token would refuse prose: `see RFC-7519`, `ISO-8601`,
    `SHA-256`. What distinguishes a hidden criterion is that it shares its PREFIX with one the
    contract does count — a contract's criteria are numbered in one family by construction, so
    `AC-2` beside a counted `AC-1` is a criterion in the wrong shape, while `RFC-7519` is not.
    A contract that hides ALL of them extracts nothing and is already refused upstream.
    """
    prefixes = {_criterion_family(cid) for cid in counted}
    hidden = {}
    for i, line in enumerate(content.splitlines(), 1):
        for token in CRIT_SHAPED_RE.findall(line):
            if token in counted:
                continue
            if _criterion_family(token) in prefixes:
                hidden.setdefault(token, i)
    return hidden


def json_contract(content):
    """The parsed contract if it is JSON declaring an explicit criterion_ids array, else None.

    That array IS the denominator — declared, machine-readable, unambiguous. Nothing is being
    scraped out of prose, so there is no prose to be fooled by, and the text heuristic below must
    not run on it (PR #308 review, P1): a valid contract whose descriptive fields mention an old
    `AC-9` beside an explicit `["AC-1"]` was refused, and the refusal told the author to use the
    very JSON array they had used.

    An array holding anything but strings raises ValueError naming the field: a list or object
    where a criterion id belongs made set() raise TypeError deep inside a check, reported only as
    an anonymous `malformed manifest: TypeError` (review P3).
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict) and isinstance(data.get("criterion_ids"), list):
        bad = [x for x in data["criterion_ids"] if not isinstance(x, str)]
        if bad:
            raise ValueError("the authoritative contract's criterion_ids must hold only "
                             f"criterion-id strings, got {bad[0]!r:.60} ({type(bad[0]).__name__})")
        return data
    return None


def extract_criterion_ids(content):
    """The authoritative criterion set, re-derived FROM the frozen source. A JSON source may declare
    `criterion_ids` — unambiguous, and PREFERRED. Otherwise the ids are the tokens that BEGIN a list
    item or line in the text (CRIT_ID_RE): `- AC-1: …` is a criterion, `see RFC-7519` is prose
    (#268)."""
    doc = json_contract(content)  # ValueError on a non-string id, named (review P3)
    if doc is not None:
        return set(doc["criterion_ids"])
    return set(CRIT_ID_RE.findall(content))


def _is_mutation(unit_class):
    """True unless the coordinator explicitly classed the unit report-only/planning. Missing or
    unknown => mutation (fail-safe), so the review + negative-control authorities run."""
    return unit_class not in ("report-only", "planning")


def check_scope(m, auth_source, auth_digest):
    """1. The denominator is the COORDINATOR's frozen contract (auth_source @ auth_digest), NOT the
    worker's manifest. A worker that drops a criterion — from criterion_ids, criteria, or by pointing
    its own contract at a shrunken source — is caught, because the authoritative content still carries
    it and only the coordinator's digest is trusted. Fail-closed without an authoritative contract."""
    if not auth_source or not auth_digest:
        return ["scope: no authoritative contract (--contract-source/--contract-digest from the "
                "dispatch record) — a worker manifest cannot certify its own denominator"]
    content, err = read_source(auth_source)
    if err:
        return [f"scope: authoritative contract unreadable ({auth_source}): {err}"]
    want = _norm_digest(auth_digest)
    got = sha256_of(content)
    if got != want:
        return [f"scope: authoritative source does not match --contract-digest ({got} != {want})"]
    text = content.decode("utf-8")
    try:
        authoritative = extract_criterion_ids(text)
    except ValueError as exc:
        return [f"scope: {exc}"]
    if not authoritative:
        return ["scope: no criterion ids in the authoritative contract"]
    doc = json_contract(text)
    if doc is not None:
        # A declared array needs no heuristic — but it can still under-declare. A16 in JSON form is
        # a `criteria` list a human reads as the spec beside a shorter `criterion_ids`, so check it
        # structurally, against the document's own ids, rather than by scanning its text.
        listed = {c.get("id") for c in (doc.get("criteria") or [])
                  if isinstance(c, dict) and isinstance(c.get("id"), str)}
        undeclared = sorted(listed - authoritative)
        if undeclared:
            return [f"scope: the authoritative contract lists {undeclared} in its criteria[] but "
                    f"leaves them out of criterion_ids, so the denominator would be "
                    f"{sorted(authoritative)} — smaller than the contract a human reads, which is "
                    "the whole scope guarantee. Declare every criterion in criterion_ids (#296)"]
    else:
        hidden = hidden_criterion_ids(text, authoritative)
        if hidden:
            where = ", ".join(f"{tok} (line {ln})" for tok, ln in sorted(hidden.items()))
            return [f"scope: the authoritative contract carries {where} in a form the extractor "
                    "does not count, beside criteria it does. The denominator would be "
                    f"{sorted(authoritative)} — smaller than the contract a human reads, which is "
                    "the whole scope guarantee. Write every criterion as a list item "
                    "(`- AC-2: …`), or use a JSON contract with an explicit criterion_ids array "
                    "(#296)"]
    # The manifest SHAPE this check reads, validated before it is read (review P3): `contract` an
    # object, `contract.digest` a string, `contract.criterion_ids` a list of strings, `criteria` a
    # list of {id: str, addressed} objects. Absent stays absent — coverage then names what is
    # missing; present and the wrong shape is a named fatal, never an exception.
    contract, criteria = m.get("contract") or {}, m.get("criteria") or []
    if not isinstance(contract, dict):
        return [f"scope: manifest `contract` must be an object, got {type(contract).__name__}"]
    if not isinstance(contract.get("digest") or "", str):
        return ["scope: manifest contract.digest must be a string, got "
                f"{type(contract['digest']).__name__}"]
    declared = contract.get("criterion_ids") or []
    if not (isinstance(declared, list) and all(isinstance(x, str) for x in declared)):
        return [f"scope: manifest contract.criterion_ids must be a list of criterion-id strings, "
                f"got {declared!r:.60}"]
    declared = set(declared)
    if not isinstance(criteria, list):
        return [f"scope: manifest `criteria` must be a list of {{id, addressed}} objects, got "
                f"{type(criteria).__name__}"]
    for i, item in enumerate(criteria):
        if not isinstance(item, dict):
            return [f"scope: manifest criteria[{i}] must be an {{id, addressed}} object, got "
                    f"{item!r:.60} ({type(item).__name__})"]
        if not isinstance(item.get("id"), str):
            return [f"scope: manifest criteria[{i}].id must be a criterion-id string, got "
                    f"{item.get('id')!r:.60}"]
    errs = []
    mdigest = contract.get("digest")
    if mdigest and _norm_digest(mdigest) != want:
        errs.append("scope: manifest contract.digest != authoritative digest (denominator swap)")
    addressed = {c["id"] for c in criteria if c.get("addressed") is True}
    unaddressed = sorted(authoritative - addressed)
    if unaddressed:
        errs.append(f"scope: authoritative criteria not addressed in criteria[] "
                    f"(absent, or addressed != true): {unaddressed}")
    undeclared = sorted(authoritative - declared)
    if undeclared:
        errs.append(f"scope shrunk: contract.criterion_ids drops authoritative ids: {undeclared}")
    return errs


def check_shas_present(m):
    return [f"missing required '{f}'" for f in ("base_sha", "head_sha") if not m.get(f)]


def check_real_commits(m, is_mutation=False):
    """2. base_sha / head_sha must be real, immutable commits. A symbolic ref like 'HEAD' resolves
    but is not a pinned commit — fatal for a mutation unit, advisory otherwise. Existence check is
    skipped outside a git repo."""
    errs = []
    for field in ("base_sha", "head_sha"):
        sha = m.get(field)
        if sha and not HEX40_RE.match(sha):
            msg = f"{field} '{sha}' is not a pinned 40-hex commit SHA (a symbolic ref is not immutable)"
            errs.append(msg if is_mutation else f"NOTE: {msg}")
    if _git(["rev-parse", "--is-inside-work-tree"])[0] != 0:
        return errs + ["NOTE: not inside a git repo — commit-existence check skipped"]
    for field in ("base_sha", "head_sha"):
        sha = m.get(field)
        if sha and str(sha).startswith("-"):
            # read_source guards its ref the same way; an option-shaped SHA must not reach
            # git as an option on ANY lane, not only the mutation lane's HEX40 gate (#382).
            errs.append(f"{field} {sha!r} is option-shaped — refusing before git sees it")
            continue
        if sha and _git(["cat-file", "-e", f"{sha}^{{commit}}"])[0] != 0:
            errs.append(f"{field} '{sha}' is not a real commit")
    return errs


def check_freshness(m):
    """A reviewed_sha, if claimed, must equal head_sha (a rebase/bot-push after review voids it) —
    UNLESS `pr.reviewed_wtree` is bound to BOTH trees: tree(reviewed_sha) == reviewed_wtree ==
    tree(head_sha), all recomputed locally (a worker-chosen 40-hex string that only matches the
    head is a forgery, not freshness). A content-identical rebase/amend does not void the review;
    any content change does (reviewed-sha-freshness.md). The SHA remains the GitHub-lookup key.
    Independent proof that the review HAPPENED is check_review (mutation units)."""
    reviewed = (m.get("pr") or {}).get("reviewed_sha")
    head = m.get("head_sha")
    if reviewed and reviewed != head and not _wtree_bound(m):
        return [f"stale review: reviewed_sha '{reviewed}' != head_sha '{head}'"]
    return []


def _tree(sha):
    code, out = _git(["rev-parse", f"{sha}^{{tree}}"])
    return out if code == 0 else None


def _wtree_bound(m):
    """True only when pr.reviewed_wtree is a 40-hex tree SHA bound to BOTH the reviewed commit's
    tree and the head's tree (a content-identical head move). Fail-closed on anything missing,
    non-hex, outside a git repo, or unresolvable."""
    pr = m.get("pr") or {}
    reviewed, head, wtree = pr.get("reviewed_sha"), m.get("head_sha"), pr.get("reviewed_wtree")
    if not (reviewed and head and wtree):
        return False
    if not all(HEX40_RE.match(str(v)) for v in (reviewed, head, wtree)):
        return False
    if _git(["rev-parse", "--is-inside-work-tree"])[0] != 0:
        return False
    rt, ht = _tree(reviewed), _tree(head)
    return rt is not None and ht is not None and rt == wtree == ht


def review_ok(reviews, head_sha, author=None, also_sha=None, equivalent_shas=()):
    """Latest independent state WITHIN this content's review history governs the veto.

    Approvals require head or the explicitly tree-bound reviewed SHA, and an approver whose
    `author_association` is in _Authority.INDEPENDENT_REVIEWER_ASSOCIATIONS. Objections use all
    authoritative equivalent trees; a worker cannot select one away. Unrelated later reviews
    do not withdraw a relevant objection. COMMENTED/DISMISSED at equivalent content still do.
    """
    ok_shas = {head_sha} | ({also_sha} if also_sha else set())
    relevant = ok_shas | set(equivalent_shas)
    latest = {}
    for r in reviews or []:
        if r.get("commit_id") in relevant:
            latest[(r.get("user") or {}).get("login")] = r
    independent = [r for who, r in latest.items() if author is None or who != author]
    if any(r.get("state") == "CHANGES_REQUESTED" for r in independent):
        return False
    return any(r.get("state") == "APPROVED" and r.get("commit_id") in ok_shas
               and r.get("author_association") in _Authority.INDEPENDENT_REVIEWER_ASSOCIATIONS
               for r in independent)


def _equivalent_review_shas(reviews, head, author, also_sha):
    """Re-derive veto scope from fetched review commits, never the manifest's selected SHA.

    A later state by the same reviewer on known equivalent content supersedes older states.
    Otherwise an unavailable object may contain a standing objection: fail closed.
    """
    known = {head} | ({also_sha} if also_sha else set())
    settled, trees = set(), {}
    for review in reversed(reviews):
        who = (review.get("user") or {}).get("login")
        if who == author or who in settled:
            continue
        sha = review.get("commit_id")
        if sha not in known:
            if head not in trees:
                trees[head] = _tree(head)
            if trees[head] is None:
                return None, "cannot resolve head tree for authoritative review history"
            if sha not in trees:
                trees[sha] = _tree(sha) if HEX40_RE.fullmatch(str(sha)) else None
            if trees[sha] is None:
                return None, f"cannot resolve historical review commit {sha!r}; fail-closed"
            if trees[sha] != trees[head]:
                continue
            known.add(sha)
        settled.add(who)
    return known, None


def parse_review_pages(out):
    """`gh api --paginate` concatenates one JSON array per page; merge them into a single list.
    Fail-closed on malformed output or a non-array page."""
    dec = json.JSONDecoder()
    items, i = [], 0
    while True:
        while i < len(out) and out[i] in " \t\r\n":
            i += 1
        if i >= len(out):
            return items, None
        try:
            obj, i = dec.raw_decode(out, i)
        except (json.JSONDecodeError, ValueError) as err:
            return None, str(err)
        if not isinstance(obj, list):
            return None, "unexpected non-array page in gh output"
        items.extend(obj)


def fetch_reviews(repo, pr_number):
    _Authority.ensure()  # a library caller that never ran main(): pin on first use, ONCE (F-1)
    if _Authority.gh is None:
        return None, _Authority.ABSENT
    if not (type(pr_number) is int and pr_number > 0):  # a path segment, never a path (P3)
        return None, f"pr.number {pr_number!r} is not a positive integer"
    # --paginate: without it GitHub returns the first 30 reviews only, and review_ok would
    # compute "latest per reviewer" over a stale window (#167). One HTTP round-trip per page,
    # so allow a longer timeout than the single-call default.
    code, out, err = _Authority.api(repo, f"pulls/{pr_number}/reviews", "--paginate", timeout=60)
    if code != 0:
        return None, (err.strip() or "gh api failed")
    return parse_review_pages(out)


def fetch_pr_author(repo, pr_number):
    if _Authority.gh is None or not (type(pr_number) is int and pr_number > 0):
        return None
    code, out, _ = _Authority.api(repo, f"pulls/{pr_number}")
    if code != 0:
        return None
    try:
        return (json.loads(out).get("user") or {}).get("login")
    except (json.JSONDecodeError, ValueError):
        return None


class _Authority:
    """The REVIEW AUTHORITY and the lane it answers on — coordinator state, resolved ONCE in main()
    at startup, before anything worker-written can execute (h409 F-1/F-2, C5/C1).

    The executed negative control runs the unit's own test code in this process's environment,
    and a bare `gh` lookup AFTER that read whatever a worker-planted stub put first on PATH — a
    same-run false GREEN (C5). So `gh` is resolved to an ABSOLUTE path here and only that path is
    ever invoked: a mid-run PATH write can no longer redirect the review leg. The resolved binary
    is then classed by CUSTODY: under a work tree, under the system temp dir, or in a
    user-writable dir that is not a standard system bin dir, it is one the graded worker could
    have replaced, and the review leg is ADVISORY-ONLY — on a lane that claims soundness (the
    ci|mcp|sdk|dispatch provenance classes, or an enforcement-mode run with a signed dispatch
    record + a PINNED pubkey) it FAILS CLOSED; on the native advisory lane the verdict records it.
    The review REPOSITORY is the same story (C1): inferred from `origin` — a remote the worker
    (and every sibling worktree) can rewrite — it is advisory; a sound lane requires --repo.
    Resolution happens EXACTLY ONCE: main() pins at startup; a library caller that never ran
    main() pins on first use (verify() before its control, fetch_reviews for direct callers).
    "gh absent when pinned" is a TERMINAL state (custody "absent"), never a reason to look again
    — the round-1 verifier treated it as unresolved and re-resolved AFTER the executed control,
    finding the stub the control had just planted (G-1: the C5 false GREEN on both lanes)."""

    SOUND_PROVENANCE = ("ci", "mcp", "sdk", "dispatch")
    # Who may cast the INDEPENDENT approval: GitHub's `author_association` on the review, read
    # from the API — never the manifest. "Not the PR author" alone let ANY account count: a
    # throwaway login (or a sock puppet of the worker) with no standing in the repository could
    # approve a PR on a public repo and satisfy the gate (review P2). Only an account the
    # repository itself grants standing — its owner, an org member, an invited collaborator —
    # approves. CONTRIBUTOR, FIRST_TIMER, FIRST_TIME_CONTRIBUTOR, MANNEQUIN and NONE never do. A
    # CHANGES_REQUESTED still vetoes from ANY non-author account (the fail-closed direction).
    # A class constant, not a module one: the RV-D2 width pin holds verify.py's top level fixed.
    INDEPENDENT_REVIEWER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
    ABSENT = ("gh absent at startup (the review authority is pinned once, before the control, "
              "and never re-resolved — h409 F-1)")
    ABSENT_GIT = "git absent at startup (pinned once, before the control, never re-resolved — h409 R2)"
    # The environment the pinned gh runs under (h409 R3): what it needs to authenticate and
    # nothing a worker could steer it with. GH_HOST / GH_CONFIG_DIR / GH_* are NOT here — the
    # host rides the coordinator's --repo (split_repo); the token passes only when present.
    GH_ENV_KEEP = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "GH_TOKEN", "GITHUB_TOKEN")
    # What any OTHER child of this verifier gets (h409 F-6 / N-4): the process-hygiene floor and
    # nothing that steers. The executed control is worker code — it runs the unit's tests, which
    # need an interpreter and a home, never the coordinator's GH_TOKEN or an ORCA_* value. git
    # and gitleaks are legs the verifier states facts through, and git's env is an exec channel
    # (GIT_EXTERNAL_DIFF, GIT_CONFIG_COUNT + core.fsmonitor, GIT_SSH_COMMAND, GIT_PROXY_COMMAND,
    # GIT_DIR/GIT_ALTERNATE_*): none passes. LC_* passes as a prefix. No identity variable is
    # needed: revert --no-commit, apply --index, worktree add/remove, diff, rev-list and
    # merge-base commit nothing; an identity, if a leg ever needs one, is HOME's gitconfig.
    AMBIENT_KEEP = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG")
    AMBIENT_KEEP_PREFIX = ("LC_",)
    # h409 N-2: named in the fetch-failure fatal so a proxied or XDG-configured host reads the
    # cause as the scrub, not as a network fault.
    SCRUB_NOTE = (" (gh ran under a scrubbed environment: XDG_CONFIG_HOME, HTTPS_PROXY/NO_PROXY and "
                  "SSL_CERT_FILE are dropped with every other steering variable — only "
                  + ", ".join(GH_ENV_KEEP) + " pass; h409 R3)")
    gh = None            # absolute path of the resolved review authority, or None (absent)
    custody = None       # "system" | "worker-writable" | "absent" (pinned, no gh) | None (UNRESOLVED)
    git = None           # absolute path of the pinned git (h409 R2), or None (absent)
    git_custody = None   # its custody class, as gh's; None = not pinned yet
    gitleaks = None      # absolute path of the pinned gitleaks, or None (absent — the built-in floor)
    gitleaks_custody = None
    lane = None          # what claims soundness ("provenance=ci", "enforcement") or None
    repo_source = None   # "explicit" | "inferred" | None

    @classmethod
    def reset(cls):
        cls.gh = cls.custody = cls.lane = cls.repo_source = None
        cls.git = cls.git_custody = cls.gitleaks = cls.gitleaks_custody = None

    @classmethod
    def pin_git(cls):
        """git is every SHA/tree/ancestry fact this verifier states, and legs of it run AFTER the
        executed control (the review-veto tree, check_symbol_on_base, the worktree teardown) — so
        it is pinned to an absolute path FIRST, before anything else resolves, and classed like gh
        (h409 R2). classify() itself reads the toplevel through git, hence the path lands before
        the class."""
        found = shutil.which("git")
        cls.git = os.path.abspath(found) if found else None
        cls.git_custody = cls.classify(cls.git) if found else "absent"

    @classmethod
    def pin_gitleaks(cls):
        """gitleaks is pinned and classed the same way (h409 R2). It can only ADD a redaction hit
        on top of the built-in floor — a replaced one yields at worst a fatal, never a false
        GREEN — so a worker-writable one is still consulted on the advisory lane, and its custody
        is recorded. On any lane claiming soundness (a provenance lane, or the enforcement lane a
        signed dispatch record and pubkey open — the predicate authority_leg applies to git) it is
        not run at all (W3-10): the coordinator's verifier does not execute a binary the graded
        worker could have replaced."""
        found = shutil.which("gitleaks")
        cls.gitleaks = os.path.abspath(found) if found else None
        cls.gitleaks_custody = cls.classify(cls.gitleaks) if found else "absent"

    @classmethod
    def git_bin(cls):
        """The pinned git for every git leg. A library caller that never ran main() pins on
        first use — before its control, as verify() ensures — and never again."""
        if cls.git is None and cls.git_custody is None:
            cls.pin_git()
        return cls.git

    @classmethod
    def resolve(cls, provenance=None, enforcement=False, explicit_repo=None):
        """Pin the authorities for this run; returns the review repo (explicit, else inferred)."""
        cls.reset()
        if provenance in cls.SOUND_PROVENANCE:
            cls.lane = f"provenance={provenance}"
        elif enforcement:
            cls.lane = "enforcement (signed dispatch record + pubkey)"
        cls.pin_git()
        found = shutil.which("gh")
        if found:
            cls.gh = os.path.abspath(found)  # the PATH entry, absolute — never a bare name again
            cls.custody = cls.classify(cls.gh)
        else:
            cls.custody = "absent"  # pinned: this run has no authority and will not look again
        cls.pin_gitleaks()
        if explicit_repo:
            cls.repo_source = "explicit"
            return explicit_repo
        inferred = infer_repo()
        cls.repo_source = "inferred" if inferred else None
        return inferred

    @staticmethod
    def anchor_commit(name):
        """gitexec.remote_tracking_commit (W3-07) run through this verifier's custody-classed git:
        (commit, target, None) when `name` is a commit id naming that commit object or a full
        refs/remotes/… ref that EXISTS under exactly that name (every symbolic hop
        remote-tracking), else (None, target, why). The one exact-name rule every trust anchor
        answers to — key_source's keys, and the refs/remotes/origin/<base> the ancestry,
        base-binding and symbol legs resolve ONCE and then read only by the commit it returns
        (with that ref absent, `rev-parse`/`merge-base`/`grep` expanded the name to a local
        refs/heads/refs/remotes/… branch). A rule that does not load is no anchor, never a pass."""
        try:
            spec = importlib.util.spec_from_file_location(
                "gitexec_for_verify", Path(__file__).resolve().parent / "gitexec.py")
            gitexec = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gitexec)
            # RAW stdout: _git strips, and str.strip() eats U+2028/U+2029/U+0085, which a
            # refname may end with; and its strict text decode would raise on a non-UTF-8 one.
            def run(*args):
                code, out, _err = _git_bytes(list(args))
                return code, out.decode("utf-8", "surrogateescape")
            return gitexec.remote_tracking_commit(run, name)
        except (OSError, ImportError, SyntaxError, AttributeError) as err:
            return None, name, f"could not be classed (gitexec.py: {err})"

    @classmethod
    def key_source(cls, source, what):
        """(where, the source to READ, pinned, refusal or None) for trust material named `path`
        or `path@ref` (W3-03).

        A bare path is read from the WORKING TREE — the graded worker's to write — and `path@main`,
        `@HEAD` or any other local name is a ref the same worker can move (W3-02's class). Both
        were accepted on a lane claiming soundness with a NOTE that said only "the supplied key",
        so the rule "pass path@<reviewed ref>" lived in prose. On ANY lane claiming soundness —
        `cls.lane`, the one predicate git, gh and gitleaks custody also answer to — a trust key is
        now read only at a commit id or a remote-tracking ref; elsewhere the read stands and
        `where` says which kind it was, so the verdict and the transcript tell them apart. A
        dispatch record with an unpinned key does not open the enforcement lane at all (main()).

        The class is decided by what the ref RESOLVES to, never by its spelling (PR #719 review),
        and the resolution is by EXACT name (W3-07, Codex review): gitexec.remote_tracking_commit,
        the rule decisions.py and gate-batch.py --pin-ref and run_report's trusted base answer to,
        run through this verifier's own custody-classed git. A commit id anchors only when it
        names that commit object (64 hex digits in a SHA-1 repository are no object id, and
        rev-parse expands them as a branch name); a ref only when it is a full refs/remotes/… name
        that EXISTS under exactly that name, every symbolic hop remote-tracking too — never what
        `rev-parse` expands it to (refs/heads/refs/remotes/… when the remote-tracking ref is
        absent), never a revision suffix (~1, ^, @{1}). It is resolved to a commit ONCE and the
        bytes are read at that commit — nothing re-resolves the name afterwards.

        What a remote-tracking ref guarantees, precisely: it is what the clone's last fetch wrote.
        On a lane claiming soundness the coordinator (or the CI runner) owns that clone, so the
        graded change did not write it. On a worker's own machine `git update-ref refs/remotes/…`
        works like any other ref write, which is why the in-session lane stays advisory."""
        path, sep, ref = (source or "").partition("@")
        sound = bool(cls.lane)  # PR #719 review round 2: provenance AND enforcement lanes
        if not (sep and ref):
            where = f"the working-tree file {path} (the graded worker can write it)"
            read, pinned = source, False
        elif ref.startswith("-"):
            return f"{path} at {ref!r}", source, False, None  # read_source refuses it
        else:
            commit, target, why = cls.anchor_commit(ref)
            if commit is not None:
                read, pinned = f"{path}@{commit}", True
                via = f" (a symbolic ref to {target})" if target not in (ref, commit) else ""
                where = (f"{path} at commit {commit[:12]}" if target == commit else
                         f"{path} at remote-tracking ref {ref}{via} = commit {commit[:12]}")
            else:
                # Not an anchor. Off a sound lane the read stands where git's own resolution puts
                # it, said to be a local name; on one it is refused below. A name that names no
                # commit at all is reported as such (a tree id, say, is no commit to anchor on).
                code, local = _git(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"])
                pinned = False
                if code != 0 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", local):
                    where, read = f"{path} at {ref!r}, which names no commit", source
                else:
                    where = (f"{path} at {ref!r} = commit {local[:12]}, a local name the graded "
                             f"worker can move ({ref!r} {why})")
                    read = f"{path}@{local}"
        if not pinned and sound:
            return where, read, False, (f"{what} {source!r} is {where} — a lane claiming soundness "
                                 f"({cls.lane}) reads trust material only at a commit id or a full "
                                 "remote-tracking ref that exists under exactly that name (what the "
                                 "coordinator's own fetch wrote): path@refs/remotes/… or "
                                 "path@<commit id>; fail-closed (W3-03, W3-07)")
        if pinned:
            # Said in every verdict, not only the docs (PR #719 re-attack): in the worker's own
            # clone `git update-ref refs/remotes/origin/main <its commit>` succeeds, and a commit id
            # names whatever the caller chose.
            where += (" — trustworthy only where the worker cannot write refs (the coordinator's "
                      "own fetch, a CI checkout); in the worker's own clone this lane is advisory")
        return where, read, pinned, None

    @classmethod
    def ensure(cls, explicit_repo=None):
        """Pin on first use for a library caller that never ran main(). A pinned run — absent
        included — is never re-resolved, so nothing the executed control planted is ever found."""
        if cls.custody is None:
            cls.resolve(explicit_repo=explicit_repo)

    @classmethod
    def _nodes(cls, path, seen=None):
        """Every filesystem object a BY-HAND resolution of `path` touches: each directory
        component, the entry itself, and — at every symlink — the link and then the components
        of its target, restarting there. Raises OSError on a missing node or a link loop, so a
        caller that cannot probe a hop cannot trust it either (h409 C-1)."""
        seen = set() if seen is None else seen
        parts = Path(path).parts
        cur = Path(parts[0])
        yield cur, os.lstat(cur)
        for i, part in enumerate(parts[1:], start=1):
            if part == ".":
                continue
            cur = cur.parent if part == ".." else cur / part  # every prior component is link-free
            st = os.lstat(cur)
            yield cur, st
            if stat.S_ISLNK(st.st_mode):
                if str(cur) in seen or len(seen) >= 40:
                    raise OSError(f"symlink loop or too many hops at {cur}")
                seen.add(str(cur))
                target = os.path.join(str(cur.parent), os.readlink(cur))  # absolute wins the join
                yield from cls._nodes(os.path.join(target, *parts[i + 1:]), seen)
                return

    @classmethod
    def _worker_controls(cls, node, st):
        """The OWNERSHIP + mode probe (h409 C-2): the effective user owns it (a 0555 of one's own
        is one `chmod u+w` from writable), a group they belong to can write it, anyone can, or
        access(2) says so (ACLs). W_OK alone was a MODE probe and classed a worker-OWNED 0555
        dir system."""
        if stat.S_ISLNK(st.st_mode):
            # a link's own bits are always 0777 and its ownership grants nothing — re-pointing or
            # removing it takes a write on its DIRECTORY (probed as the node before it), and its
            # target's hops are walked by _nodes. Without this, /bin -> usr/bin (ubuntu) classes
            # every /bin/* worker-writable (CI on #493).
            return False
        if st.st_uid == os.geteuid():
            return True
        if st.st_mode & stat.S_IWOTH:
            return True
        if st.st_mode & stat.S_IWGRP and st.st_gid in {os.getegid(), *os.getgroups()}:
            return True
        return os.access(node, os.W_OK)

    @classmethod
    def classify(cls, path):
        """"worker-writable" when the binary, ANY directory on the way to it, or ANY symlink hop
        lies under a work tree or the temp dir, or is something this user OWNS or can write —
        "system" only when every node from `/` to the final target is beyond the worker's reach.
        Custody is a PROBE, never a name: round 2 short-circuited to "system" on a list of
        system bin dir names, two of which are user-writable on every Homebrew host (h409 R1).
        Round 3 probed only the RESOLVED parent by W_OK, so a worker-planted symlink in a
        writable dir pointing at /bin/sh (C-1) and a worker-OWNED 0555 dir (C-2) both classed
        system. A genuinely root-owned /usr/bin still classes system: root owns every hop."""
        try:
            nodes = list(cls._nodes(os.path.abspath(path)))
            p = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            return "worker-writable"
        for root in (tempfile.gettempdir(), os.getcwd(), _toplevel(), _evidence_toplevel()):
            if root:
                try:
                    r = Path(root).resolve()
                except OSError:
                    continue
                if r == Path(r.anchor):  # cwd "/" is every path's parent; the probe covers it (R-2)
                    continue
                if p == r or r in p.parents or any(n == r or r in n.parents for n, _ in nodes):
                    return "worker-writable"
        if any(cls._worker_controls(n, st) for n, st in nodes):
            return "worker-writable"
        return "system"

    @classmethod
    def split_repo(cls, repo):
        """`host/owner/name` → (host, "owner/name"); `owner/name` → (None, repo). The host is the
        coordinator's when it rides the pinned --repo; nothing in the environment names one."""
        parts = (repo or "").split("/")
        if len(parts) == 3 and all(parts):
            return parts[0], f"{parts[1]}/{parts[2]}"
        return None, repo

    @classmethod
    def gh_env(cls):
        """The scrubbed environment the pinned gh runs under (h409 R3)."""
        return {k: os.environ[k] for k in cls.GH_ENV_KEEP if k in os.environ}

    @classmethod
    def nc_env(cls):
        """The scrubbed environment the EXECUTED CONTROL runs under (h409 F-6): the ambient
        floor only — no GH_*/GITHUB_*, no ORCA_*, no GIT_*, nothing else the verifier holds.
        Relative and empty PATH entries are dropped so worktree/cwd binaries cannot shadow PATH."""
        env = {k: v for k, v in os.environ.items()
               if k in cls.AMBIENT_KEEP or k.startswith(cls.AMBIENT_KEEP_PREFIX)}
        if "PATH" in env:
            env["PATH"] = os.pathsep.join(
                p for p in env["PATH"].split(os.pathsep) if p and os.path.isabs(p))
        return env

    @classmethod
    def unreplayable_tool(cls, m, nc, tool):
        """True when a mutation-tool control under --execute-nc quotes no unified diff to replay."""
        if tool in ("revert", "hand"):
            return False
        art = nc.get("artifact")
        if not (isinstance(art, str) and art):
            return True
        raw, err = read_artifact(m, art)
        if err or raw is None:
            return True
        return not bool(_extract_diff(raw.decode("utf-8", "replace")))

    _SHELL_NAMES = frozenset({
        "sh", "bash", "rbash", "dash", "zsh", "rzsh", "ksh", "rksh", "ash", "hush", "csh", "tcsh",
    })
    _SHELL_RE = re.compile(
        r"(?:sh|bash|rbash|dash|zsh|rzsh|ksh|rksh|mksh|pdksh|yash|posh|ash|hush|csh|tcsh)(?:[-.]?\d+(?:\.\d+)*)?"
    )
    _MULTICALL_BOX_RE = re.compile(r"(?:busybox|toybox|sbase-box|ubase-box)(?:[.-][A-Za-z0-9_.-]+)?")
    _MUX_RE = re.compile(
        r"(?:(?:g?sed|gnused|[gmn]?awk|deno|bun)(?:[-.]?\d+(?:\.\d+)*)?"
        r"|(?:busybox|toybox|sbase-box|ubase-box)(?:[.-][A-Za-z0-9_.-]+)?"
        r"|ld\.so(?:\.[0-9]+)?|ld-linux[A-Za-z0-9_.-]*|ld-musl[A-Za-z0-9_.-]*"
        r"|proxychains[0-9]*)"
    )

    @classmethod
    def _is_shell_name(cls, name):
        return name in cls._SHELL_NAMES or bool(cls._SHELL_RE.fullmatch(name))

    @classmethod
    def _is_mux_exe(cls, name):
        return name in cls._NC_FORBID_MUX_EXES or bool(cls._MUX_RE.fullmatch(name))

    @classmethod
    def _exec_family(cls, name):
        if cls._MULTICALL_BOX_RE.fullmatch(name):
            return "multicall_box"
        if cls._is_mux_exe(name):
            return "mux_wrapper"
        if name in ("env", "genv"):
            return "wrap:env"
        if name in ("nice", "gnice"):
            return "wrap:nice"
        if name in ("timeout", "gtimeout"):
            return "wrap:timeout"
        if name in ("nohup", "gnohup"):
            return "wrap:nohup"
        if name in ("command", "builtin"):
            return f"wrap:{name}"
        if re.fullmatch(r"(?:csh|tcsh|r?zsh)(?:[-.]?\d+(?:\.\d+)*)?", name):
            return "shell:non_posix"
        if cls._is_shell_name(name):
            return "shell:posix"
        for k, pat in (
            ("interp:python", r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:node", r"node(?:js)?(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:perl", r"perl(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:ruby", r"ruby(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:php", r"php(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:lua", r"lua(?:jit)?(?:[-.]?\d+(?:\.\d+)*)?"),
            ("interp:Rscript", r"Rscript(?:[-.]?\d+(?:\.\d+)*)?"),
            ("runner:pytest", r"(?:pytest|py\.test)(?:[-.]?\d+(?:\.\d+)*)?"),
            ("runner:make", r"g?make(?:[-.]?\d+(?:\.\d+)*)?"),
            ("runner:grep", r"(?:[efg]?grep)(?:[-.]?\d+(?:\.\d+)*)?"),
            ("runner:rg", r"(?:rg|ripgrep)(?:[-.]?\d+(?:\.\d+)*)?"),
        ):
            if re.fullmatch(pat, name):
                return k
        return None
    _SAFE_SHELL_O_OPTIONS = frozenset({
        "allexport", "braceexpand", "errexit", "errtrace", "functrace",
        "hashall", "histexpand", "monitor", "noclobber", "noexec",
        "noglob", "notify", "nounset", "physical", "pipefail", "posix",
        "verbose", "xtrace",
    })
    _NC_FORBID_ENV_VARS = frozenset({
        "PATH", "IFS", "CDPATH", "ENV", "BASH_ENV",
        "SHELLOPTS", "BASHOPTS", "BASH_LOADABLES_PATH", "BASH_COMPAT",
        "POSIXLY_CORRECT", "ZDOTDIR", "FPATH", "GLOBIGNORE", "EXECIGNORE",
        "PROMPT_COMMAND", "PS0", "PS4",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GLIBC_TUNABLES",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONSAFEPATH",
        "PYTHONPYCACHEPREFIX", "PYTHONWARNINGS", "PYTHONINSPECT",
        "PYTHONUSERBASE", "VIRTUAL_ENV",
        "NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE",
        "DENO_DIR", "BUN_INSTALL",
        "PERL5OPT", "PERL5LIB", "PERLLIB",
        "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
        "AWKPATH", "AWKLIBPATH",
        "PHPRC", "PHP_INI_SCAN_DIR",
        "R_PROFILE", "R_PROFILE_USER", "R_ENVIRON", "R_ENVIRON_USER",
        "R_LIBS", "R_LIBS_USER", "R_LIBS_SITE",
        "HOME", "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "GH_CONFIG_DIR",
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    })
    _NC_FORBID_ENV_PREFIXES = (
        "GIT_", "ORCA_", "OPEN_FLEET_", "GH_", "GITHUB_",
        "LD_", "DYLD_", "LUA_", "BASH_FUNC_",
        "PYTHON", "NODE_", "PERL", "RUBY", "GEM_", "BUNDLE_",
        "DENO_", "BUN_", "AWK", "PHP", "R_",
    )
    _NC_FORBID_MUX_EXES = frozenset({
        "busybox", "toybox", "sbase-box", "ubase-box",
        "xargs", "gxargs", "find", "gfind", "stdbuf", "setsid", "flock", "chrt", "ionice",
        "taskset", "prlimit", "choom", "uclampset", "numactl", "eatmydata", "chronic",
        "script", "expect", "screen", "tmux", "ssh",
        "su", "sudo", "doas", "pkexec", "runuser", "dzdo", "pfexec",
        "chroot", "arch-chroot", "fakeroot", "fakechroot", "nsenter", "unshare",
        "bwrap", "firejail", "proot", "time", "parallel", "watch",
        "strace", "ltrace", "gdb", "lldb", "perf", "valgrind",
        "torsocks", "tsocks", "proxychains", "proxychains4", "catchsegv",
        "fish", "elvish", "nu", "nushell", "xonsh", "pwsh", "powershell", "rc", "es",
        "sed", "awk", "gawk", "mawk", "nawk", "deno", "bun",
    })

    @classmethod
    def _env_var_forbidden(cls, var_name):
        if "[" in var_name or "]" in var_name:
            return True
        up = var_name.upper()
        if up in cls._NC_FORBID_ENV_VARS:
            return True
        return up.startswith(cls._NC_FORBID_ENV_PREFIXES)

    @classmethod
    def _parse_shell_script_operand(cls, tok, rest):
        """Parse shell argv tail `rest` and return `(script_op, err)` enforcing staged repo-relative path."""
        if re.fullmatch(r"(?:csh|tcsh|r?zsh)(?:[-.]?\d+(?:\.\d+)*)?", Path(tok).name):
            return None, f"proof executable {tok!r} invokes non-POSIX shell or zsh startup files; fail-closed (#750 C19)"
        si = 0
        while si < len(rest):
            arg = rest[si]
            if arg in ("--", "-"):
                si += 1
                break
            if not arg.startswith(("-", "+")) or arg == "+":
                break
            if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
                return None, (f"proof executable {tok!r} invokes a shell -c command string, "
                              "whose inner commands are unverified (#750 C19)")
            if arg.startswith("--"):
                if arg in ("--posix", "--norc", "--noprofile"):
                    si += 1
                    continue
                return None, (f"proof executable {tok!r} uses unsupported shell option {arg!r}; "
                              "fail-closed (#750 C19)")
            if arg in ("-O", "+O"):
                return None, (f"proof executable {tok!r} {arg} alters shell lookup/parsing; "
                              "fail-closed (#750 C19)")
            if arg in ("-o", "+o"):
                if si + 1 >= len(rest) or rest[si + 1] not in cls._SAFE_SHELL_O_OPTIONS:
                    return None, (f"proof executable {tok!r} {arg} missing or unsupported option; "
                                  "fail-closed (#750 C19)")
                si += 2
                continue
            short = arg[1:]
            if arg.startswith("-") and any(ch in short for ch in ("l", "i", "s", "r")):
                return None, (f"proof executable {tok!r} invokes interactive/login/stdin shell mode; "
                              "fail-closed (#750 C19)")
            if any(ch not in "abefhmnuvxBCHP" for ch in short):
                return None, (f"proof executable {tok!r} uses unsupported shell option {arg!r}; "
                              "fail-closed (#750 C19)")
            if "o" in short or "O" in short:
                if not (short.endswith(("o", "O")) and (short.count("o") + short.count("O") == 1)) or si + 1 >= len(rest):
                    return None, f"proof executable {tok!r} uses ambiguous -o option cluster (#750 C19)"
                si += 2
                continue
            si += 1
        if si >= len(rest):
            return None, (f"proof executable {tok!r} invokes shell without a script operand; "
                          "fail-closed (#750 C19)")
        script_op = rest[si]
        if "/" not in script_op or os.path.isabs(script_op) or ".." in Path(script_op).parts:
            return None, (f"proof executable {tok!r} uses bare or external shell script operand "
                          f"{script_op!r}; require a staged repo-relative path containing '/'; "
                          "fail-closed (#750 C19)")
        return script_op, None

    @classmethod
    def _check_rel_operand(cls, tok, op, label="script"):
        if not op or os.path.isabs(op) or ".." in Path(op).parts:
            return f"proof executable {tok!r} targets external {label} {op!r} outside the staged commit; fail-closed (#750 C19)"
        return None

    @classmethod
    def _parse_target_operands(cls, tok, rest):
        """Validate non-shell interpreter/runner options in `rest` and return `(staged_rel_files, err)`."""
        name = Path(tok).name
        staged = []
        program = name
        scan_idx = 0
        if re.fullmatch(r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?", name):
            pi = 0
            while pi < len(rest) and rest[pi] in {
                "-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-u", "-q",
            }:
                pi += 1
            if pi >= len(rest):
                return None, f"proof executable {tok!r} missing module or script target; fail-closed (#750 C19)"
            if rest[pi].startswith("-m"):
                mod = (rest[pi + 1] if pi + 1 < len(rest) else "") if rest[pi] == "-m" else rest[pi][2:]
                if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", mod):
                    return None, f"proof executable {tok!r} uses invalid -m module {mod!r}; fail-closed (#750 C19)"
                scan_idx = pi + 2 if rest[pi] == "-m" else pi + 1
                if mod in ("pytest", "unittest"):
                    program = mod
                else:
                    mod_root = mod.split(".", 1)[0]
                    forbid_mods = (
                        (set(getattr(sys, "stdlib_module_names", ())) | set(sys.builtin_module_names)) - {"unittest"}
                    ) | {"pip", "setuptools", "wheel", "virtualenv", "nox", "tox", "coverage", "ipython", "IPython"}
                    if mod_root in forbid_mods:
                        return None, (
                            f"unsupported proof command: {tok!r} invokes module runner '-m {mod}'; "
                            "only '-m pytest', '-m unittest', or a staged repo module is permitted (#750 C19)"
                        )
                    if "-I" in rest[:pi]:
                        return None, (
                            f"unsupported proof command: {tok!r} cannot combine '-I' with repo module '-m {mod}'; "
                            "fail-closed (#750 C19)"
                        )
                    program = "py_module"
            else:
                if rest[pi] == "--":
                    pi += 1
                if pi >= len(rest) or rest[pi].startswith("-"):
                    bad_opt = rest[pi] if pi < len(rest) else "--"
                    return None, (f"proof executable {tok!r} uses unsupported interpreter option "
                                  f"{bad_opt!r} or missing script; fail-closed (#750 C19)")
                err = cls._check_rel_operand(tok, rest[pi], "script")
                if err:
                    return None, err
                staged.append(rest[pi])
                scan_idx = pi + 1
        elif re.fullmatch(r"(?:node(?:js)?|ruby|perl|php|lua(?:jit)?|Rscript)(?:[-.]?\d+(?:\.\d+)*)?", name):
            pi = 1 if rest[:1] == ["--"] else 0
            if pi >= len(rest) or rest[pi].startswith("-"):
                bad_opt = rest[pi] if pi < len(rest) else ""
                return None, (f"proof executable {tok!r} uses unsupported interpreter option "
                              f"{bad_opt!r} or missing script; fail-closed (#750 C19)")
            if name.startswith("node") and rest[pi] in ("inspect", "debug"):
                return None, f"proof executable {tok!r} invokes debugger subcommand {rest[pi]!r}; fail-closed (#750 C19)"
            err = cls._check_rel_operand(tok, rest[pi], "script")
            if err:
                return None, err
            staged.append(rest[pi])
            scan_idx = pi + 1
        elif re.fullmatch(r"g?make(?:[-.]?\d+(?:\.\d+)*)?", name):
            mi = 0
            while mi < len(rest):
                a = rest[mi]
                if a in ("-f", "--file", "--makefile"):
                    if mi + 1 >= len(rest):
                        return None, f"proof executable {tok!r} {a} missing makefile operand; fail-closed (#750 C19)"
                    err = cls._check_rel_operand(tok, rest[mi + 1], "makefile")
                    if err:
                        return None, err
                    staged.append(rest[mi + 1])
                    mi += 2
                elif a.startswith(("--file=", "--makefile=")):
                    val = a.split("=", 1)[1]
                    err = cls._check_rel_operand(tok, val, "makefile")
                    if err:
                        return None, err
                    staged.append(val)
                    mi += 1
                elif a.startswith("-f") and len(a) > 2:
                    val = a[2:]
                    err = cls._check_rel_operand(tok, val, "makefile")
                    if err:
                        return None, err
                    staged.append(val)
                    mi += 1
                elif a.startswith("-") or "=" in a:
                    return None, f"proof executable {tok!r} uses unsupported make argument {a!r}; fail-closed (#750 C19)"
                else:
                    mi += 1
            return staged, None
        elif re.fullmatch(r"(?:pytest|py\.test)(?:[-.]?\d+(?:\.\d+)*)?", name):
            program = "pytest"
        elif re.fullmatch(r"(?:[efg]?grep)(?:[-.]?\d+(?:\.\d+)*)?", name):
            program = "grep"

        if program == "unittest":
            ui, u_after, u_pos = scan_idx, False, []
            while ui < len(rest):
                ua = rest[ui]
                if not u_after and ua == "--":
                    u_after = True
                    ui += 1
                    continue
                if u_after or not ua.startswith("-"):
                    u_pos.append(ua)
                    ui += 1
                    continue
                if ua in ("-s", "--start-directory", "-t", "--top-level-directory"):
                    if ui + 1 >= len(rest):
                        return None, f"proof executable {tok!r} {ua} missing directory operand; fail-closed (#750 C19)"
                    err = cls._check_rel_operand(tok, rest[ui + 1], "unittest directory")
                    if err:
                        return None, err
                    ui += 2
                    continue
                if ua.startswith(("--start-directory=", "--top-level-directory=")):
                    err = cls._check_rel_operand(tok, ua.split("=", 1)[1], "unittest directory")
                    if err:
                        return None, err
                    ui += 1
                    continue
                if ua.startswith(("-s", "-t")) and len(ua) > 2:
                    err = cls._check_rel_operand(tok, ua[2:], "unittest directory")
                    if err:
                        return None, err
                    ui += 1
                    continue
                if ua in ("-p", "--pattern", "-k"):
                    if ui + 1 >= len(rest):
                        return None, f"proof executable {tok!r} {ua} missing operand; fail-closed (#750 C19)"
                    ui += 2
                    continue
                if ua.startswith(("--pattern=", "-p", "-k")) and len(ua) > 2:
                    ui += 1
                    continue
                if len(ua) > 1 and ua[0] == "-" and ua[1] != "-" and any(ch in ua[1:] for ch in ("s", "t", "p", "k")):
                    return None, f"proof executable {tok!r} uses ambiguous unittest option cluster {ua!r}; fail-closed (#750 C19)"
                ui += 1
            if u_pos[:1] == ["discover"]:
                for d_dir in u_pos[1:2] + u_pos[3:4]:
                    err = cls._check_rel_operand(tok, d_dir, "unittest directory")
                    if err:
                        return None, err
            else:
                for u_op in u_pos:
                    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", u_op):
                        err = cls._check_rel_operand(tok, u_op, "unittest target")
                        if err:
                            return None, err
            return staged, None

        value_opts = ("-f",) + (("-c",) if program == "pytest" else ())
        long_opts = ("--config", "--config-file", "--file")
        saw_grep_pat = False
        grep_pos = []
        i = scan_idx
        while i < len(rest):
            a = rest[i]
            if a == "--":
                break
            if program == "pytest":
                if (
                    a in ("-o", "-p", "--override-ini", "--rootdir", "--confcutdir", "--basetemp", "--import-mode", "--pyargs")
                    or a.startswith(("--override-ini=", "--rootdir=", "--confcutdir=", "--basetemp=", "--import-mode="))
                    or (len(a) > 1 and a[0] == "-" and a[1] != "-" and any(ch in a[1:] for ch in ("o", "p")))
                ):
                    return None, f"proof executable {tok!r} uses dynamic pytest config/plugin option {a!r}; fail-closed (#750 C19)"
                if a in ("-k", "-m", "-W", "--maxfail"):
                    if i + 1 >= len(rest):
                        return None, f"proof executable {tok!r} {a} missing operand; fail-closed (#750 C19)"
                    i += 2
                    continue
                if a.startswith(("-k", "-m", "-W")) and len(a) > 2:
                    i += 1
                    continue
                if len(a) > 1 and a[0] == "-" and a[1] != "-" and any(ch in a[1:] for ch in ("k", "m", "W")):
                    return None, f"proof executable {tok!r} uses ambiguous pytest option cluster {a!r}; fail-closed (#750 C19)"
            if program == "grep":
                if a in ("-e", "--regexp"):
                    if i + 1 >= len(rest):
                        return None, f"proof executable {tok!r} {a} missing pattern; fail-closed (#750 C19)"
                    saw_grep_pat = True
                    i += 2
                    continue
                if a.startswith("--regexp=") or (a.startswith("-e") and len(a) > 2):
                    saw_grep_pat = True
                    i += 1
                    continue
            if a.startswith(tuple(opt + "=" for opt in long_opts)):
                val = a.split("=", 1)[1]
                err = cls._check_rel_operand(tok, val, "config")
                if err:
                    return None, err
                staged.append(val)
                if program == "grep":
                    saw_grep_pat = True
            elif a in long_opts:
                if i + 1 >= len(rest):
                    return None, f"proof executable {tok!r} {a} missing operand; fail-closed (#750 C19)"
                err = cls._check_rel_operand(tok, rest[i + 1], "config")
                if err:
                    return None, err
                staged.append(rest[i + 1])
                if program == "grep":
                    saw_grep_pat = True
                i += 1
            elif a in value_opts:
                if i + 1 >= len(rest):
                    return None, f"proof executable {tok!r} {a} missing operand; fail-closed (#750 C19)"
                err = cls._check_rel_operand(tok, rest[i + 1], "config")
                if err:
                    return None, err
                staged.append(rest[i + 1])
                if program == "grep":
                    saw_grep_pat = True
                i += 1
            elif a.startswith(value_opts) and len(a) > 2:
                val = a[2:]
                err = cls._check_rel_operand(tok, val, "config")
                if err:
                    return None, err
                staged.append(val)
                if program == "grep":
                    saw_grep_pat = True
            elif len(a) > 1 and a[0] == "-" and a[1] != "-" and any(opt[1] in a[1:] for opt in value_opts):
                return None, f"proof executable {tok!r} uses ambiguous option cluster {a!r}; fail-closed (#750 C19)"
            elif program == "pytest" and not a.startswith("-"):
                p_part = a.split("::", 1)[0]
                err = cls._check_rel_operand(tok, p_part, "test path")
                if err:
                    return None, err
            elif program == "py_module":
                if a.startswith("-"):
                    return None, (
                        f"unsupported proof command: {tok!r} passes unsupported option {a!r} to '-m {mod}'; "
                        "fail-closed (#750 C19)"
                    )
                err = cls._check_rel_operand(tok, a, "operand")
                if err:
                    return None, err
                staged.append(a)
            elif program == "grep" and not a.startswith("-"):
                grep_pos.append(a)
            i += 1
        if i < len(rest) and rest[i] == "--":
            if program == "pytest":
                for post_a in rest[i + 1:]:
                    p_part = post_a.split("::", 1)[0]
                    err = cls._check_rel_operand(tok, p_part, "test path")
                    if err:
                        return None, err
            elif program == "py_module":
                for post_a in rest[i + 1:]:
                    err = cls._check_rel_operand(tok, post_a, "operand")
                    if err:
                        return None, err
                    staged.append(post_a)
            elif program == "grep":
                grep_pos.extend(rest[i + 1:])
        if program == "grep":
            file_ops = grep_pos if saw_grep_pat else grep_pos[1:]
            for g_file in file_ops:
                err = cls._check_rel_operand(tok, g_file, "file")
                if err:
                    return None, err
        return staged, None

    @classmethod
    def _python_module_target(cls, argv):
        """Return dotted `-m <mod>` target when `argv` runs Python module mode outside pytest/unittest."""
        indexed, err = cls._unwrap_nc_indexed(argv)
        if err or not indexed:
            return None
        target_idx, target_tok = indexed[-1]
        tail = argv[target_idx + 1:]
        if not re.fullmatch(r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?", Path(target_tok).name):
            return None
        pi = 0
        while pi < len(tail) and tail[pi] in {"-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-u", "-q"}:
            pi += 1
        if pi >= len(tail) or not tail[pi].startswith("-m"):
            return None
        mod = (tail[pi + 1] if pi + 1 < len(tail) else "") if tail[pi] == "-m" else tail[pi][2:]
        return None if (not mod or mod in ("pytest", "unittest")) else mod

    @classmethod
    def _staged_script_operands(cls, argv):
        """Return repo-relative script/config operands that must exist and remain invariant in each phase."""
        indexed, err = cls._unwrap_nc_indexed(argv)
        if err or not indexed:
            return []
        target_idx, target_tok = indexed[-1]
        tail = argv[target_idx + 1:]
        if cls._is_shell_name(Path(target_tok).name):
            sh_op, s_err = cls._parse_shell_script_operand(target_tok, tail)
            return [] if (s_err or sh_op is None) else [sh_op]
        ops, t_err = cls._parse_target_operands(target_tok, tail)
        return [] if (t_err or not ops) else ops

    @classmethod
    def _verify_staged_rel_file(cls, repo_dir, rel_path):
        """Verify `rel_path` stays strictly inside `repo_dir` across relative hops (never checking
        host ancestors above `repo_dir`) and is a non-group/world-writable regular file."""
        try:
            repo_real = Path(repo_dir).resolve(strict=True)
            norm_rel = os.path.normpath(rel_path)
            if os.path.isabs(rel_path) or norm_rel in ("", ".") or ".." in Path(norm_rel).parts:
                return None, f"proof input {rel_path!r} escapes the staged commit; fail-closed (#750 C19)"
            cur = repo_real
            for part in Path(norm_rel).parts:
                if part in ("", "."):
                    continue
                cur = cur / part
                lst = os.lstat(cur)
                if stat.S_ISLNK(lst.st_mode):
                    cur = cur.resolve(strict=True)
                    if cur != repo_real and repo_real not in cur.parents:
                        return None, (f"proof input {rel_path!r} resolves via symlink outside "
                                      "the staged commit; fail-closed (#750 C19)")
            final_real = cur.resolve(strict=True)
            st = os.stat(final_real)
            if (
                final_real == repo_real
                or repo_real not in final_real.parents
                or not stat.S_ISREG(st.st_mode)
                or (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            ):
                return None, (f"proof input {rel_path!r} is missing, writable, or escapes "
                              "the staged commit; fail-closed (#750 C19)")
            return hashlib.sha256(final_real.read_bytes()).hexdigest(), None
        except (OSError, RuntimeError) as exc:
            return None, (f"proof input {rel_path!r} does not exist in staged commit ({exc}); "
                          "fail-closed (#750 C19)")

    @classmethod
    def _shell_script_operand(cls, argv):
        """Return the repo-relative shell script operand when `argv` invokes a shell, else `None`."""
        indexed, err = cls._unwrap_nc_indexed(argv)
        if err or not indexed:
            return None
        target_idx, target_tok = indexed[-1]
        if not cls._is_shell_name(Path(target_tok).name):
            return None
        script_op, s_err = cls._parse_shell_script_operand(target_tok, argv[target_idx + 1:])
        return None if s_err else script_op

    @classmethod
    def _unwrap_nc_indexed(cls, argv):
        """Extract `[(argv_idx, tok), ...]` across wrappers, failing closed on lookup/env/shell bypasses."""
        indexed = []
        idx = 0
        while idx < len(argv):
            tok = argv[idx]
            name = Path(tok).name
            if tok.startswith("-") or name.startswith("-"):
                return None, (f"proof executable {tok!r} starts with '-', triggering login-shell startup "
                              "or ambiguous option dispatch; fail-closed (#750 C19)")
            if cls._is_mux_exe(name):
                return None, (f"proof executable {tok!r} multiplexes inner commands whose targets "
                              "cannot be statically pinned; fail-closed (#750 C19)")
            indexed.append((idx, tok))
            rest = argv[idx + 1:]
            if cls._is_shell_name(name):
                _, sh_err = cls._parse_shell_script_operand(tok, rest)
                if sh_err:
                    return None, sh_err
                break
            idx += 1
            if name in ("env", "genv"):
                while idx < len(argv):
                    a = argv[idx]
                    if a == "--":
                        idx += 1
                        break
                    if a in ("-", "-i", "--ignore-environment"):
                        return None, "env -i/--ignore-environment alters PATH lookup context; fail-closed (#750 C19)"
                    if not a.startswith("-"):
                        break
                    if a in ("-S", "--split-string") or a.startswith("--split-string="):
                        return None, "env -S/--split-string performs runtime word splitting; fail-closed (#750 C19)"
                    if a in ("-C", "--chdir") or a.startswith("--chdir="):
                        return None, "env -C/--chdir alters working-directory lookup context; fail-closed (#750 C19)"
                    if a in ("-P", "--default-path") or a.startswith("--default-path="):
                        return None, "env -P/--default-path alters PATH lookup context; fail-closed (#750 C19)"
                    if a in ("-u", "--unset") or a.startswith("--unset="):
                        if a.startswith("--unset="):
                            uvar = a.split("=", 1)[1]
                            idx += 1
                        elif idx + 1 < len(argv):
                            uvar = argv[idx + 1]
                            idx += 2
                        else:
                            return None, "env -u/--unset missing variable name; fail-closed (#750 C19)"
                        if not uvar or cls._env_var_forbidden(uvar):
                            return None, f"env unset {uvar!r} alters executable lookup context; fail-closed (#750 C19)"
                        continue
                    if a.startswith("--"):
                        if a in ("--null", "--debug", "--list-signal-handling") or a.startswith(
                            ("--block-signal", "--default-signal", "--ignore-signal")
                        ):
                            idx += 1
                            continue
                        return None, f"env option {a!r} is unsupported; fail-closed (#750 C19)"
                    short = a[1:]
                    si = 0
                    consumed_next = False
                    while si < len(short):
                        ch = short[si]
                        rem = short[si + 1:]
                        if ch in ("0", "v"):
                            si += 1
                            continue
                        if ch == "i":
                            return None, "env -i alters PATH lookup context; fail-closed (#750 C19)"
                        if ch in ("S", "C", "P"):
                            return None, f"env -{ch} alters execution/lookup context; fail-closed (#750 C19)"
                        if ch == "u":
                            if rem:
                                uvar = rem
                            elif idx + 1 < len(argv):
                                uvar = argv[idx + 1]
                                consumed_next = True
                            else:
                                return None, "env -u missing variable name; fail-closed (#750 C19)"
                            if not uvar or cls._env_var_forbidden(uvar):
                                return None, f"env -u {uvar!r} alters executable lookup context; fail-closed (#750 C19)"
                            break
                        return None, f"env option -{ch} is unsupported; fail-closed (#750 C19)"
                    idx += 2 if consumed_next else 1
                while idx < len(argv) and "=" in argv[idx]:
                    lhs = argv[idx].split("=", 1)[0]
                    if not lhs or cls._env_var_forbidden(lhs):
                        return None, f"env assignment {lhs!r} alters executable lookup context; fail-closed (#750 C19)"
                    idx += 1
                if idx >= len(argv):
                    return None, "env wrapper has no target proof command; fail-closed (#750 C19)"
            elif name == "command":
                while idx < len(argv) and argv[idx].startswith("-") and len(argv[idx]) > 1:
                    if argv[idx] == "--":
                        idx += 1
                        break
                    return None, f"command option {argv[idx]!r} alters lookup/execution; fail-closed (#750 C19)"
                if idx >= len(argv):
                    return None, "command wrapper has no target proof command; fail-closed (#750 C19)"
            elif name in ("nohup", "gnohup"):
                while idx < len(argv) and argv[idx].startswith("-") and len(argv[idx]) > 1:
                    if argv[idx] == "--":
                        idx += 1
                        break
                    return None, f"nohup option {argv[idx]!r} is unsupported; fail-closed (#750 C19)"
                if idx >= len(argv):
                    return None, "nohup wrapper has no target proof command; fail-closed (#750 C19)"
            elif name in ("nice", "gnice"):
                while idx < len(argv) and argv[idx].startswith("-") and len(argv[idx]) > 1:
                    opt = argv[idx]
                    if opt == "--":
                        idx += 1
                        break
                    if opt in ("-n", "--adjustment"):
                        if idx + 1 >= len(argv):
                            return None, f"nice {opt} missing adjustment value; fail-closed (#750 C19)"
                        idx += 2
                    elif opt.startswith(("-n", "--adjustment=")) or re.match(r"^--?\d+$", opt):
                        idx += 1
                    else:
                        return None, f"nice option {opt!r} is unsupported; fail-closed (#750 C19)"
                if idx >= len(argv):
                    return None, "nice wrapper has no target proof command; fail-closed (#750 C19)"
            elif name in ("timeout", "gtimeout"):
                while idx < len(argv) and argv[idx].startswith("-") and len(argv[idx]) > 1:
                    opt = argv[idx]
                    if opt == "--":
                        idx += 1
                        break
                    if opt in ("-k", "--kill-after", "-s", "--signal"):
                        if idx + 1 >= len(argv):
                            return None, f"timeout {opt} missing argument; fail-closed (#750 C19)"
                        idx += 2
                    elif opt in ("-v", "--verbose", "--foreground", "--preserve-status") or opt.startswith(
                        ("-k", "--kill-after=", "-s", "--signal=")
                    ):
                        idx += 1
                    elif not opt.startswith("--") and opt[1:].endswith(("k", "s")) and all(
                        c == "v" for c in opt[1:-1]
                    ):
                        if idx + 1 >= len(argv):
                            return None, f"timeout {opt} missing argument; fail-closed (#750 C19)"
                        idx += 2
                    else:
                        return None, f"timeout option {opt!r} is unsupported; fail-closed (#750 C19)"
                if idx + 1 >= len(argv):
                    return None, "timeout wrapper missing duration or target proof command; fail-closed (#750 C19)"
                idx += 1  # duration operand
            else:
                _, t_err = cls._parse_target_operands(tok, rest)
                if t_err:
                    return None, t_err
                break
        return indexed, None

    @classmethod
    def _unwrap_nc_tokens(cls, argv):
        """Extract all wrapper and target executable tokens from `argv`, refusing shell `-c`."""
        indexed, err = cls._unwrap_nc_indexed(argv)
        if err or indexed is None:
            return None, err
        return [tok for _, tok in indexed], None

    @classmethod
    def _verify_exec_file_and_shebang(cls, resolved, label, roots, search_path, _depth=0):
        """Verify executable `resolved` and any `#!` interpreter chain, returning `(chain, err)`."""
        if _depth > 4:
            return None, f"proof executable {label!r} exceeds shebang nesting depth; fail-closed (#750 C19)"
        try:
            abs_path = os.path.abspath(resolved)
            nodes = list(cls._nodes(abs_path))
            real = Path(abs_path).resolve(strict=True)
            st = os.stat(real)
            if not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
                return None, f"proof executable {label!r} is not an executable regular file ({real})"
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None, (f"proof executable {label!r} ({real}) is group- or world-writable; "
                              "fail-closed (#750 C19)")
            for n, nst in nodes:
                if stat.S_ISLNK(nst.st_mode):
                    continue
                if (nst.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) and not (
                        stat.S_ISDIR(nst.st_mode) and (nst.st_mode & stat.S_ISVTX)):
                    return None, (f"proof executable {label!r} resolves through writable node {n}; "
                                  "fail-closed (#750 C19)")
            raw_bytes = real.read_bytes()
            digest = hashlib.sha256(raw_bytes).hexdigest()
        except (OSError, RuntimeError) as exc:
            return None, f"proof executable {label!r} cannot be verified ({exc})"
        for r in roots:
            if real == r or r in real.parents or any(n == r or r in n.parents for n, _ in nodes):
                return None, (f"proof executable {label!r} resolves inside the repository "
                              f"worktree ({real}); fail-closed")
        hop_sig = tuple((str(n), stat.S_IFMT(nst.st_mode), nst.st_dev, nst.st_ino)
                        for n, nst in nodes)
        self_rec = (abs_path, str(real), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, digest, hop_sig)
        if not raw_bytes.startswith(b"#!"):
            return (self_rec,), None
        nl = raw_bytes.find(b"\n")
        first_line = raw_bytes[2:nl] if nl != -1 else raw_bytes[2:]
        if b"\r" in first_line or b"\x00" in first_line or (nl == -1 and len(raw_bytes) > 255) or len(first_line) > 253:
            return None, f"proof executable {label!r} has malformed or CR-terminated shebang; fail-closed (#750 C19)"
        line_str = first_line.decode("utf-8", errors="surrogateescape").strip(" \t")
        parts = re.split(r"[ \t]+", line_str, maxsplit=1) if line_str else []
        interp = parts[0] if parts else ""
        interp_arg = parts[1].strip(" \t") if len(parts) > 1 else ""
        if not interp or not interp.startswith("/"):
            return None, f"proof executable {label!r} uses relative or empty shebang interpreter {interp!r}; fail-closed (#750 C19)"
        sub_chain, sub_err = cls._verify_exec_file_and_shebang(
            interp, f"{label}#!{interp}", roots, search_path, _depth + 1
        )
        if sub_err:
            return None, sub_err
        i_base = Path(interp).name
        i_real_base = Path(sub_chain[0][1]).name
        eff_i_real_base = (
            i_base
            if (cls._MULTICALL_BOX_RE.fullmatch(i_real_base) and not cls._MULTICALL_BOX_RE.fullmatch(i_base))
            else i_real_base
        )
        interp_names = {i_base, eff_i_real_base}
        if (
            cls._is_mux_exe(i_base)
            or cls._is_mux_exe(eff_i_real_base)
            or (interp_names & {"nice", "gnice", "timeout", "gtimeout", "nohup", "gnohup", "command", "builtin"})
            or any(re.fullmatch(r"(?:csh|tcsh)(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names)
            or (i_base != "sh" and any(re.fullmatch(r"r?zsh(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names))
        ):
            return None, (f"proof executable {label!r} uses multiplexer or wrapper shebang {interp!r}; "
                          "fail-closed (#750 C19)")
        if interp_names & {"env", "genv"}:
            if not interp_arg or interp_arg.startswith("-") or "=" in interp_arg or any(c in interp_arg for c in " \t"):
                return None, (f"proof executable {label!r} shebang env argument {interp_arg!r} "
                              "alters lookup or splits options; fail-closed (#750 C19)")
            env_resolved = interp_arg if os.path.isabs(interp_arg) else shutil.which(interp_arg, path=search_path)
            if not env_resolved:
                return None, (f"proof executable {label!r} shebang env target {interp_arg!r} "
                              "cannot be resolved on the scrubbed PATH; fail-closed (#750 C19)")
            env_chain, env_err = cls._verify_exec_file_and_shebang(
                env_resolved, f"{label}#!env:{interp_arg}", roots, search_path, _depth + 1
            )
            if env_err:
                return None, env_err
            e_base = Path(interp_arg).name
            e_real_base = Path(env_chain[0][1]).name
            eff_e_real_base = (
                e_base
                if (cls._MULTICALL_BOX_RE.fullmatch(e_real_base) and not cls._MULTICALL_BOX_RE.fullmatch(e_base))
                else e_real_base
            )
            e_names = {e_base, eff_e_real_base}
            if (
                cls._is_mux_exe(e_base)
                or cls._is_mux_exe(eff_e_real_base)
                or (e_names & {"env", "genv", "nice", "gnice", "timeout", "gtimeout", "nohup", "gnohup", "command", "builtin"})
                or any(re.fullmatch(r"(?:csh|tcsh)(?:[-.]?\d+(?:\.\d+)*)?", n) for n in e_names)
                or (e_base != "sh" and any(re.fullmatch(r"r?zsh(?:[-.]?\d+(?:\.\d+)*)?", n) for n in e_names))
            ):
                return None, (f"proof executable {label!r} shebang env target {interp_arg!r} "
                              "resolves to multiplexer or wrapper; fail-closed (#750 C19)")
            return (self_rec, *sub_chain, *env_chain), None
        if interp_arg and not cls._shebang_arg_allowed(interp_names, interp_arg):
            return None, (f"proof executable {label!r} shebang option {interp_arg!r} "
                          "cannot be statically pinned; fail-closed (#750 C19)")
        return (self_rec, *sub_chain), None

    @staticmethod
    def _shebang_arg_allowed(interp_names, interp_arg):
        if not interp_arg:
            return True
        if any(re.fullmatch(r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names):
            return bool(re.fullmatch(r"-[BEIOPSsuq]+", interp_arg))
        if any(re.fullmatch(r"(?:sh|bash|dash|ash|ksh|mksh|yash)(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names):
            return bool(re.fullmatch(r"-[abefhmnuvxBCEHP]+", interp_arg))
        if any(re.fullmatch(r"perl(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names):
            return bool(re.fullmatch(r"-[wTt]+", interp_arg))
        if any(re.fullmatch(r"(?:[gmnb]?awk|sed|[gs]sed)(?:[-.]?\d+(?:\.\d+)*)?", n) for n in interp_names):
            return interp_arg == "-f"
        return False

    @classmethod
    def nc_exec_identity(cls, argv, top=None, path_env=None, expected=None, when=None):
        """Resolve and fingerprint the proof executable(s) in `argv` (#750 C19).
        Refuses executables that cannot be resolved on the scrubbed PATH, invoke shell `-c`, are
        group/world-writable, or have any path/symlink hop inside the target or evidence worktree
        or a group/world-writable non-sticky directory. Returns (records, err)."""
        if not argv:
            return None, "negative_control.command is empty after parsing"
        indexed, wrap_err = cls._unwrap_nc_indexed(argv)
        if wrap_err or indexed is None:
            return None, wrap_err
        search_path = cls.nc_env().get("PATH", "") if path_env is None else path_env
        roots = []
        for root in (top, _toplevel(), _evidence_toplevel()):
            if root:
                try:
                    r = Path(root).resolve()
                except OSError:
                    continue
                if r != Path(r.anchor):
                    roots.append(r)
        records = []
        for argv_idx, tok in indexed:
            resolved = tok if os.path.isabs(tok) else shutil.which(tok, path=search_path)
            if not resolved:
                return None, f"proof executable {tok!r} cannot be resolved on the scrubbed PATH"
            chain, chain_err = cls._verify_exec_file_and_shebang(resolved, tok, roots, search_path)
            if chain_err:
                return None, chain_err
            tok_base = Path(tok).name
            real_base = Path(chain[0][1]).name
            eff_real_base = (
                tok_base
                if (cls._MULTICALL_BOX_RE.fullmatch(real_base) and not cls._MULTICALL_BOX_RE.fullmatch(tok_base))
                else real_base
            )
            real_fam = cls._exec_family(eff_real_base)
            tok_fam = cls._exec_family(tok_base)
            sh_emulated_zsh = (
                tok_base == "sh"
                and real_fam == "shell:non_posix"
                and bool(re.fullmatch(r"r?zsh(?:[-.]?\d+(?:\.\d+)*)?", eff_real_base))
            )
            if real_fam is not None and real_fam != tok_fam and not sh_emulated_zsh:
                return None, (f"proof executable {tok!r} resolves to {chain[0][1]!r} ({real_fam}) "
                              "via alias; invoke the canonical tool name so operands are verified (#750 C19)")
            records.append((argv_idx, tok, *chain[0], chain[1:]))
        out = tuple(records)
        if expected is not None and out != expected:
            return None, f"proof executable changed {when} phase; fail-closed"
        return out, None

    @staticmethod
    def quiet_oss_authorized(source, digest):
        """True only when the digest-verified coordinator JSON contract explicitly authorizes
        the oss-contribute quiet-PR lane (`mission == 'oss-contribute'` or `allow_quiet_oss: true`)."""
        if not (source and digest):
            return False
        raw, err = read_source(source)
        if err or raw is None or sha256_of(raw) != _norm_digest(digest):
            return False
        try:
            doc = json_contract(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        if not isinstance(doc, dict):
            return False
        return doc.get("mission") == "oss-contribute" or doc.get("allow_quiet_oss") is True

    @classmethod
    def quiet_oss_review(cls, m, reviews, head, author, equivalent, review_shas,
                         corroborated, nc_executed, oss_authorized=False):
        """#750 C15: an oss-contribute unit parked `awaiting-maintainer-merge` targets an upstream
        repository the fleet does not control, so upstream OWNER/MEMBER/COLLABORATOR approval may be
        absent while feedback is quiet. Accept it on the gh lane ONLY when the coordinator's
        digest-bound contract authorizes `oss-contribute`, the manifest declares
        `awaiting-maintainer-merge`, no upstream reviewer has a standing CHANGES_REQUESTED veto on
        this content, `review.artifact` is readable and binds `head_sha`, and the negative control
        was EXECUTED."""
        if not oss_authorized:
            return False, []
        parked = m.get("parked") if isinstance(m.get("parked"), list) else []
        is_quiet_oss = any(isinstance(p, dict) and p.get("reason") == "awaiting-maintainer-merge"
                           for p in parked)
        if not is_quiet_oss:
            return False, []
        ok_shas = {head} | ({equivalent} if equivalent else set())
        relevant = ok_shas | set(review_shas or ())
        latest_by_user = {}
        for rev in reviews or []:
            if rev.get("commit_id") in relevant:
                latest_by_user[(rev.get("user") or {}).get("login")] = rev
        non_author = [rev for who, rev in latest_by_user.items() if author is None or who != author]
        if any(rev.get("state") == "CHANGES_REQUESTED" for rev in non_author):
            return False, []
        art = (m.get("review") or {}).get("artifact")
        if not (isinstance(art, str) and art):
            return False, []
        raw, err = read_artifact(m, art)
        if err or raw is None or (head and head not in raw.decode("utf-8", "replace")):
            return False, []
        if not corroborated or not nc_executed:
            return False, []
        return True, [
            "NOTE: oss-contribute quiet PR (awaiting-maintainer-merge) — coordinator contract "
            "authorizes oss-contribute, no upstream CHANGES_REQUESTED veto, internal "
            "review.artifact bound to head_sha, and negative control EXECUTED"
        ]

    @staticmethod
    def unexecuted_nc_note(is_mut, nc_executed, fatal):
        """#750 C10: disclose when a mutation unit's negative control was only statically
        corroborated from its artifact rather than executed."""
        if is_mut and not nc_executed and not fatal:
            return ["NOTE: negative control corroborated from artifact only (--execute-nc not set) "
                    "— static corroboration, not an executed control"]
        return []

    @classmethod
    def git_env(cls):
        """The scrubbed environment every git and gitleaks leg runs under (h409 N-4) — the same
        floor as the control's, plus constants that stop a leg waiting on a credential prompt
        and close the config-driven execution channels (h409 B4/B5): the GIT_CONFIG_* env pairs
        carry `-c` precedence over repo-local config (B5: a `core.fsmonitor` in the graded
        repo's own .git/config), and /dev/null + NOSYSTEM drop the global and system files
        (B4: ~/.gitconfig). `safe.directory=*` replaces the one legitimate use of the global
        file (CI ownership belts) so exotic images fail nowhere new. Applied unconditionally,
        as gh's is: the launch env is the worker's on the native lane.

        The belt also closes the two OBJECT-REWRITE channels: `git replace <head> <other>` (a
        refs/replace/* entry in the shared clone) makes every leg that resolves head_sha read
        another commit's tree, parents and content, and a `.git/info/grafts` file rewrites a
        commit's parents, so ancestry and range diffs answer for a history that never existed.
        GIT_NO_REPLACE_OBJECTS=1 makes git ignore replace refs; GIT_GRAFT_FILE=/dev/null points
        the graft lookup at an empty file, so a planted grafts file is never read.

        And the HOOK channel (2026-10-23 review, P1-2): `worktree add` and `checkout <base> --
        <paths>` each run `post-checkout` from the source repo's `$GIT_COMMON_DIR/hooks` (or a
        repo-local `core.hooksPath`) as this uid, and the shared `.git` is the graded worker's to
        write on the native lane and in every worktree layout docs/verify-gate.md describes. A
        hook could stage a failing test into the control commit. `core.hooksPath=/dev/null` at
        `-c` precedence points every hook lookup at a path with no hooks under it."""
        return {**cls.nc_env(), "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull,
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": "4",
                "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_KEY_1": "protocol.ext.allow", "GIT_CONFIG_VALUE_1": "never",
                "GIT_CONFIG_KEY_2": "safe.directory", "GIT_CONFIG_VALUE_2": "*",
                "GIT_CONFIG_KEY_3": "core.hooksPath", "GIT_CONFIG_VALUE_3": os.devnull}

    # gitexec.driver_blanks, mirrored rather than called: gitexec.py is in the toolchain since
    # #608 (via inventory.py), but its copy runs gitexec's GIT under the caller's whole env, and
    # every verifier git leg runs the custody-pinned git_bin() under git_env() — so does this.
    # A config key named here is the ONLY source of a filter/diff-driver command, and `-c`
    # cannot wildcard the <driver>. tests/test_gitexec_config_commands.py holds it to gitexec's.
    # BYTES: a driver name is any bytes git accepts, and the attribute selects exactly those. A
    # filter is neutralised whole — commands blank AND required=false, or git dies on it (#649).
    # A merge.<driver>.driver (run when revert/apply/checkout 3-way-merges a path) is overridden
    # to `exit 1`: a shell builtin that fails the merge closed and runs no repo command (#649).
    _FILTER_KEY_RE = re.compile(rb"\Afilter\.(.+)\.[^.]+\Z", re.S)
    _DIFF_COMMAND_KEY_RE = re.compile(rb"\Adiff\.(?:.+)\.(?:textconv|command)\Z", re.S)
    _MERGE_KEY_RE = re.compile(rb"\Amerge\.(.+)\.[^.]+\Z", re.S)
    _FILTER_BLANKS = ((b"clean", ""), (b"smudge", ""), (b"process", ""), (b"required", "false"))
    _MERGE_DRIVER = "exit 1"

    class DriverQueryFailed(OSError):
        """driver_blanks could not read the config: never "no drivers", which would populate the
        control with every planted driver live (PR #649 review, PRRT_kwDOTWxN9c6vzAIE)."""

    @classmethod
    def driver_blanks(cls, repo):
        """`(key, value)` config pairs blanking every filter/diff driver command `repo`'s config
        declares (#629), for blanked_env(). In the executed control `repo` is the scratch worktree,
        whose config is the verifier's own (control_git_dir: it declares none), so this is a belt
        there that keeps the fail-closed refusal below. A negative-control `checkout`/`apply` MATERIALISES worker content,
        which runs a clean/smudge filter a `.gitattributes` (or `$GIT_DIR/info/attributes`, past
        any `--attr-source`) line selects — the one channel git_env's fixed belt and
        `--no-textconv`/`--no-ext-diff` cannot close. The command comes only from a declared
        `filter.<n>.*`/`diff.<n>.*` key, so the names are read from the repo's own config (listed
        under the scrubbed env, repo-local keys only) and each blanked; empty = git runs no
        command. Fail-closed to the empty list on a git error — the fixed belt stays in force.
        Read as BYTES (_run_bytes: a text decode of a 0xff name either raises or names another
        driver) and each key handed back through os.fsdecode, which subprocess reverses, so git
        gets exactly the bytes it declared (PR #649 review). Each declared filter also gets
        `required=false`: git dies on a required filter that runs nothing, which made a planted
        `required=true` fail the control's `worktree add` or `checkout` (PR #649 review)."""
        code, out, err = _run_bytes([cls.git_bin(), "-C", str(repo), "config", "--list", "-z",
                                     "--name-only"], env=cls.git_env())
        # [] means exactly "none declared" (an empty valid config is exit 0, no output); a failed,
        # timed-out (_run_bytes reports it as code 1) or unparseable query raises (PR #649 review).
        if code != 0:
            raise cls.DriverQueryFailed(f"git config --list exited {code}: {err.strip()[:200]}")
        if out and not out.endswith(b"\0"):
            raise cls.DriverQueryFailed("git config --list printed output that is not "
                                        "NUL-terminated keys")
        keys = out.split(b"\0")[:-1] if out else []
        if any(not key for key in keys):
            raise cls.DriverQueryFailed("git config --list printed an empty key")
        pairs, filt_seen, merge_seen = [], set(), set()
        for key in keys:
            filt = cls._FILTER_KEY_RE.match(key)
            merge = cls._MERGE_KEY_RE.match(key)
            if filt:
                if filt.group(1) not in filt_seen:
                    filt_seen.add(filt.group(1))
                    pairs += [(os.fsdecode(b"filter." + filt.group(1) + b"." + var), value)
                              for var, value in cls._FILTER_BLANKS]
            elif merge:
                if merge.group(1) not in merge_seen:
                    merge_seen.add(merge.group(1))
                    pairs.append((os.fsdecode(b"merge." + merge.group(1) + b".driver"),
                                  cls._MERGE_DRIVER))
            elif cls._DIFF_COMMAND_KEY_RE.match(key):
                pairs.append((os.fsdecode(key), ""))
        return pairs

    @classmethod
    def blanked_env(cls, blanks):
        """git_env() with driver_blanks pairs appended as further GIT_CONFIG_KEY_n/VALUE_n: an env
        pair keeps a key and value apart, so a driver name holding `=` (which `-c <key>=` splits
        at its first `=`) is blanked as itself, not as a different, shorter key."""
        env = cls.git_env()
        first = int(env["GIT_CONFIG_COUNT"])
        for i, (key, value) in enumerate(blanks, start=first):
            env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = key, value
        env["GIT_CONFIG_COUNT"] = str(first + len(blanks))
        return env

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def gitexec():
        """runtime/scripts/gitexec.py, loaded once by path (it is in _Transcript.TOOLCHAIN since
        #608): the verifier takes only its git custody dir builder (custody_git_dir), which runs
        no git — every verifier git leg stays on the pinned git_bin() under git_env()."""
        spec = importlib.util.spec_from_file_location(
            "verify_gitexec", Path(__file__).resolve().parent / "gitexec.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @classmethod
    def control_git_dir(cls, top, head):
        """The git dir the executed control is checked out, applied and sealed in (W4 custody
        sweep), as a context manager yielding its path: built by the verifier (gitexec
        custody_git_dir), never a linked worktree of `top`. A linked worktree reads the SHARED
        config and `info/attributes` the graded worker writes, so a filter, textconv or merge driver
        it added after driver_blanks listed the config ran in the control's checkout, revert or
        apply as this verifier. This dir's config declares no driver at all, so one a
        `.gitattributes` (or the source's `info/attributes`) selects is undefined here, whenever it
        was added. Its `objects` is the source's store ("shared"): the sealed control commit lands
        where each phase repository's alternates already reach. HEAD is `head`; `core.bare` is
        false, as the control's work tree reaches it through a `.git` gitfile. The source's
        `info/attributes` and the content of its own `core.attributesFile` ride as data. Raises
        OSError (GitCustodyRefused for an unreadable or non-regular `info/exclude`/`shallow`/
        `info/attributes`, or a `core.attributesFile` that is not a bounded regular file)."""
        git, env = cls.git_bin(), cls.git_env()
        code, common, gerr = _run([git, "-C", top, "rev-parse", "--path-format=absolute",
                                   "--git-common-dir"], timeout=30, env=env)
        code2, fmt, gerr2 = _run([git, "-C", top, "rev-parse", "--show-object-format"],
                                 timeout=30, env=env)
        if code != 0 or code2 != 0 or not common.strip():
            raise OSError(f"cannot locate the source repository's object store: {(gerr or gerr2).strip()}")

        def run(args):  # the source's own core.attributesFile, read under git_env (data only)
            # Not _run_bytes: it reports a timeout as exit 1, which `config --get` means "unset", so
            # a timed-out query read as "no attributes file" (Codex on PR #724, round 6). A timeout
            # here is an OSError: the "could not create the control worktree" refusal.
            try:
                return subprocess.run([git, "-C", top, *args], capture_output=True, timeout=30, env=env,
                                      stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired as exc:
                raise OSError(f"git {' '.join(args[:2])} timed out after {exc.timeout}s") from exc
        attributes = cls.gitexec().custody_attributes(run, top)
        return cls.gitexec().custody_git_dir(common.rstrip("\n"), fmt.strip(), str(head), None,
                                             objects="shared", bare=False, attributes=attributes)

    @classmethod
    def api(cls, repo, endpoint, *flags, timeout=20):
        """The one seam every GitHub read goes through: the PINNED gh (F-1), invoked with a
        SCRUBBED environment (h409 R3) — the ambient env is worker-influenceable on the native
        lane, and `GH_HOST`/`GH_CONFIG_DIR` in it would point even a genuine gh at a forged host.
        The host is the coordinator's: a `--repo host/owner/name` opts in via `--hostname`."""
        host, slug = cls.split_repo(repo)
        args = [cls.gh, "api", *flags, *(["--hostname", host] if host else []),
                f"repos/{slug}/{endpoint}"]
        return _run(args, timeout=timeout, env=cls.gh_env())

    @classmethod
    def authority_leg(cls):
        """The lines the OTHER pinned authorities owe (h409 R2), for every unit class: a fatal on
        a sound lane whose git is worker-influenceable, a NOTE on the advisory lane; a
        worker-writable gitleaks is a NOTE on every lane (it cannot lower the floor)."""
        lines = []
        if cls.git_custody == "worker-writable":
            where = f"git at {cls.git} is worker-writable"
            if cls.lane:
                return [f"authority: {where} — a lane claiming soundness ({cls.lane}) cannot take "
                        "its commit, tree and ancestry facts from a binary the graded worker could "
                        "have replaced; fail-closed (h409 R2)"]
            lines.append(f"NOTE: authority: advisory ({where})")
        if cls.gitleaks_custody == "worker-writable" and cls.lane:
            # W3-10: on a sound lane a binary the graded worker could have replaced is not RUN by
            # the coordinator's verifier at all — its "clean" is not additive evidence there.
            lines.append(f"NOTE: redaction: gitleaks at {cls.gitleaks} is worker-writable — on a "
                         f"lane claiming soundness ({cls.lane}) it is NOT run; only the built-in "
                         "floor scanned the evidence (W3-10)")
        elif cls.gitleaks_custody == "worker-writable":
            lines.append(f"NOTE: redaction: gitleaks at {cls.gitleaks} is worker-writable — it can "
                         "only add hits above the built-in floor, so it is consulted and recorded (h409 R2)")
        return lines

    @classmethod
    def review_leg(cls, repo):
        """The lines the GitHub review leg owes before it consults anything: a fatal on a sound
        lane whose authority is worker-influenceable, NOTEs on the advisory lane, [] when clean."""
        lines = []
        if cls.custody == "absent":
            if cls.lane:
                return [f"review_authority: {cls.ABSENT} — a lane claiming soundness ({cls.lane}) has "
                        "no independent review authority to consult; fail-closed"]
            lines.append(f"NOTE: review_authority: advisory ({cls.ABSENT})")
        if cls.custody == "worker-writable":
            where = f"gh at {cls.gh} is worker-writable"
            if cls.lane:
                return [f"review_authority: {where} — a lane claiming soundness ({cls.lane}) cannot "
                        "take its independent review from a binary the graded worker could have "
                        "replaced; fail-closed (h409 F-1)"]
            lines.append(f"NOTE: review_authority: advisory ({where})")
        if cls.repo_source == "inferred":
            if cls.lane:
                return [f"review_repo: {repo!r} was inferred from the clone's origin, which the "
                        f"worker controls — a lane claiming soundness ({cls.lane}) requires an "
                        "explicit --repo; fail-closed (h409 F-2)"]
            lines.append(f"NOTE: review_repo: advisory ({repo!r} inferred from origin, not pinned "
                         "by the coordinator)")
        return lines


def check_review(m, repo, is_mutation, no_gh=False, corroborated=False, dispatch_lighting=None,
                 nc_executed=False, allow_static_nc=True, oss_authorized=False):
    """3. A mutation unit needs an INDEPENDENT review at head_sha. Default: an APPROVED GitHub review
    looked up on GitHub (a worker-set reviewed_sha is not evidence). Fail-closed.

    #256 — the two WAIVER lanes. A dark-eligible unit (a COORDINATOR dispatch decision,
    gate-classification.md) lands without a build-blind human review, and the sanctioned no-gh /
    offline lane (dispatch --no-gh; merge-serialization.md) replaces GitHub with a local reviewer
    artifact. In BOTH the negative control becomes the entire oracle, so both now require an
    EXECUTED control (`nc_executed`, from check_negative_control under --execute-nc) on top of the
    out-of-band coordinator contract. Static corroboration is necessary and NOT sufficient: the
    artifact is worker-written either way."""
    waiver_needs_executed_nc = (
        "{lane}: the independent review is WAIVED in this lane, so the negative control is the ONLY "
        "oracle left — and a control that was merely READ is a text file the worker wrote. It must be "
        "EXECUTED (--execute-nc / ORCA_EXECUTE_NC) and go RED. Fail-closed (#256; docs/reviews/2026-09-10-review.md A1/A2/A4/"
        "A6/A9 all landed on exactly this)")
    if not is_mutation:
        return []
    if dispatch_lighting == "dark-eligible":
        if not corroborated:
            return ["dark-eligible mutation: review is waived, so the negative-control oracle must be "
                    "unfakeable — but without an out-of-band coordinator contract (--contract-source + "
                    "--contract-digest) the worker-produced artifact is forgeable; fail-closed "
                    "(gate-classification.md)"]
        if not nc_executed:
            return [waiver_needs_executed_nc.format(lane="dark-eligible mutation")]
        return ["NOTE: independent review waived — dark-eligible unit (gate-classification.md); the "
                "EXECUTED negative control + tests are the oracle, not a human review"]
    head = m.get("head_sha")
    if no_gh:
        art = (m.get("review") or {}).get("artifact")
        if not art:
            return ["no-gh mutation unit: missing review.artifact (a local reviewer record at head_sha)"]
        content, err = read_artifact(m, art)
        if err:
            return [f"no-gh mutation unit: review.artifact unreadable ({art}): {err}"]
        if head and head not in content.decode("utf-8", "replace"):
            return ["no-gh mutation unit: review.artifact does not reference head_sha"]
        if not corroborated:
            return ["no-gh mutation unit: review.artifact is worker-forgeable without an out-of-band "
                    "coordinator contract (--contract-source + --contract-digest) — fail-closed "
                    "(sign the dispatch record; merge-serialization.md)"]
        if not nc_executed:
            return [waiver_needs_executed_nc.format(lane="no-gh mutation unit")]
        return ["NOTE: no-gh review is coordinator-attested via the frozen out-of-band contract (local "
                "reviewer artifact at head_sha) plus an EXECUTED negative control, not GitHub-verified "
                "— the weaker guarantee (merge-serialization.md)"]
    number = (m.get("pr") or {}).get("number")
    if not number:
        return ["mutation unit: no pr.number to look up an independent review — unreviewed"]
    if not (type(number) is int and number > 0):
        # The manifest is worker-written and the number is interpolated into the `gh api` PATH
        # (`repos/<slug>/pulls/<n>/reviews`): `"7/../../other"` or `"7?per_page=1"` would steer
        # which resource answers. github.com refuses dot-segments today; this does not rely on
        # it (2026-10-23 review, P3). A JSON integer, positive, and nothing else.
        return [f"mutation unit: pr.number {number!r} is not a positive integer — it names the "
                "GitHub resource the review is read from, so anything else is refused; fail-closed"]
    if not repo:
        return ["mutation unit: --repo not resolvable — cannot verify the review independently"]
    authority = _Authority.review_leg(repo)
    if any(not line.startswith("NOTE:") for line in authority):
        return authority
    reviews, err = fetch_reviews(repo, number)
    if err:  # the advisory NOTEs stay on the record beside the refusal they explain
        return authority + [f"mutation unit: cannot fetch reviews for {repo}#{number} ({err}) — fail-closed"
                            + ("" if _Authority.custody == "absent" else _Authority.SCRUB_NOTE)]
    author = fetch_pr_author(repo, number)
    if author is None:
        return [f"mutation unit: cannot resolve PR author for {repo}#{number} — cannot exclude the "
                "author's self-review, fail-closed"]
    equivalent = (m.get("pr") or {}).get("reviewed_sha") if _wtree_bound(m) else None
    review_shas, err = _equivalent_review_shas(reviews, head, author, equivalent)
    if err:
        return [f"mutation unit: cannot establish INDEPENDENT APPROVED review: {err}"]
    if not review_ok(reviews, head, author, also_sha=equivalent, equivalent_shas=review_shas):
        oss_ok, oss_notes = _Authority.quiet_oss_review(
            m, reviews, head, author, equivalent, review_shas, corroborated, nc_executed,
            oss_authorized=oss_authorized)
        if oss_ok:
            return authority + oss_notes
        return [f"mutation unit: no INDEPENDENT APPROVED review at head_sha on {repo}#{number} "
                f"(the PR author's own approval, superseded reviews, and approvals from accounts "
                f"whose author_association is not one of "
                f"{sorted(_Authority.INDEPENDENT_REVIEWER_ASSOCIATIONS)} do not count; a review at "
                f"reviewed_sha only counts when reviewed_wtree binds its tree to the head's)"]
    if not nc_executed and not allow_static_nc:
        return authority + ["mutation unit: negative control was NOT executed — pass --execute-nc "
                            "(and --nc-command) so the control is re-run, or pass --allow-static-nc "
                            "to accept artifact-only corroboration explicitly (#750 C10)"]
    return authority  # [] or the advisory NOTEs (h409 F-1/F-2)


NC_TIMEOUT_S = 600


def _run_at(cwd, args, timeout=20, stdin_bytes=None, env=None):
    """Run a command in `cwd` with an optional stdin payload. argv only — never shell=True, so a
    manifest string can never become a shell command. `env` is never None from a caller here:
    a git leg passes git_env(), the control nc_env() (h409 F-6/N-4). Returns (code, stdout, stderr).
    With no payload the child gets /dev/null, never this process's stdin (#629)."""
    if args[0] is None:
        return 124, "", _Authority.ABSENT_GIT
    feed = {"input": stdin_bytes} if stdin_bytes is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout, check=False,
                           env=env, **feed)
        return (p.returncode, p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except (subprocess.TimeoutExpired, OSError) as err:
        return 124, "", str(err)


def _nc_command(nc, override):
    """The criterion-bound command the control must turn RED. Returns (argv, err).

    The command is NOT taken on the worker's word — and not on the ledger's either. Both are
    documents the graded worker writes: `negative_control.command` directly, and the `commands[]`
    records that once justified it via `evidence-run.py`, which runs on the worker and records
    what the worker hands it. Binding the one to the other is circular. A worker that writes both
    can nominate `grep -q FIXED calc.py` as its "criterion-bound proof", record it green at
    head_sha's tree, and clear the executed-control gate without ever running a test
    (docs/reviews/2026-09-11 §4 A12/A15; #279).

    So the only admissible source is `override`: the coordinator's `--nc-command`, supplied out of
    band the way `--contract-source` is. The manifest must still name a command, and it must AGREE
    with the coordinator's, so a worker cannot quietly swap the proof command underneath a
    coordinator who named one.
    """
    raw = nc.get("command")
    if not (isinstance(raw, str) and raw.strip()):
        return None, ("negative_control.command (the criterion-bound proof command, as a string) is "
                      "REQUIRED to execute the control — without it there is nothing to turn RED")
    try:
        argv = shlex.split(raw)
    except ValueError as err:
        return None, f"negative_control.command is not parseable as a command line ({err})"
    if not argv:
        return None, "negative_control.command is empty after parsing"
    line = shlex.join(argv)

    if override is None:
        return None, (
            "--execute-nc requires --nc-command: the criterion-bound proof command must come from "
            "the coordinator, out of band, exactly as --contract-source does. The manifest nominates "
            f"{line!r} — and the manifest is written by the graded worker, as is the `commands[]` "
            "ledger, so neither can authorise the other; fail-closed (#279)")
    try:
        want = shlex.split(override)
    except ValueError as err:
        return None, f"--nc-command is not parseable as a command line ({err})"
    if not want:
        return None, "--nc-command is empty after parsing"
    if shlex.join(want) != line:
        return None, (f"negative_control.command {line!r} is not the command the coordinator "
                      f"supplied out of band ({shlex.join(want)!r}) — a unit does not get to "
                      "choose what proves it; fail-closed")
    if _command_oracle_paths(override) is None:
        return None, "unsupported proof command: cannot establish executable oracle inputs"
    return want, None


def _fresh_command_records(m):
    """`commands[]` records with exit 0 whose wtree is head_sha's tree. Returns (records, err).

    The freshness rule `check_commands` (its only caller) applies. The executed negative control
    does NOT read this ledger: since #279 its command comes from the coordinator's --nc-command,
    because the ledger is worker-written and cannot authorise the proof that grades the worker.
    What the ledger still proves is narrower — the named command ran green on this content, as
    the worker's own runner recorded it (#352; 2026-10-23 review, P3: this docstring said the
    replay bound to it).
    """
    head = m.get("head_sha")
    if not head:
        return [], "commands ledger: head_sha is missing, so no record can be bound to content"
    code, want = _git(["rev-parse", f"{head}^{{tree}}"])
    if code != 0 or not want:
        return [], ("commands ledger: cannot resolve the tree of head_sha — the recorded run cannot "
                    "be bound to content; fail-closed")
    records = [c for c in (m.get("commands") or []) if isinstance(c, dict)]
    # `exit` must be the integer 0: False == 0 in Python, and a hand-written `"exit": false` read
    # as a clean run (2026-10-26 review).
    return [c for c in records
            if type(c.get("exit")) is int and c.get("exit") == 0 and c.get("wtree") == want], None


@functools.lru_cache(maxsize=1)
def _load_diff_scope():
    """diff_scope.py, loaded the way _load_ed25519 loads its sibling. It owns the repo's one
    definition of what a test path is (SCOPE_TESTS), and the control-binding checks below need
    exactly that definition — a second copy here would drift from the lens gate's copy.

    Loaded ONCE per process (review P3): _is_test_path asks per changed path, several times per
    path across the bind checks, and each ask used to re-read and re-execute the module. A
    failed load raises and is not cached, so a missing sibling still fails closed every time."""
    spec = importlib.util.spec_from_file_location(
        "diff_scope", Path(__file__).resolve().parent / "diff_scope.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _is_test_path(path):
    """True when diff_scope classifies `path` as SCOPE_TESTS on its path alone. Content rules are
    deliberately not consulted: the file may not exist at the tree we are asking about."""
    try:
        ds = _load_diff_scope()
    except Exception:  # noqa: BLE001 - a missing/unloadable sibling must not open the gate
        return None
    low = str(path).lower()
    for flag, pattern in ds.PATH_RULES:
        if flag == "TESTS" and pattern.search(low):
            return True
    return False


# A report-only unit produces prose. Everything else is code, decided by EXTENSION and nothing
# else: the first cut asked diff_scope's PATH_RULES whether a path looked like docs or tests, and
# those patterns match on names, so `src/docs/parser.py` and `src/test_runner.py` classified as
# non-code and carried a downgrade through (PR #308 review, P1). A directory called docs/ does not
# make a .py file prose. Extensions can be lied about too, but only by renaming the source file,
# which is a change a reader sees in the diff.
_PROSE_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".org"})


def _production_changes(base, head):
    """Changed paths that are not prose — the CODE a report-only unit must not touch.

    Deliberately not _changed_paths' split. There the question serves the #280 control bind — may
    this path be reverted to prove behaviour? — and a doc is not behaviour, so it counts as
    production. Here the question is whether the unit changed code at all, and a report that writes
    a document is the honest shape of a report-only unit, not a mutation in disguise (#310).

    Tests count as code here, which is stricter than the first cut. A report-only unit editing the
    oracle under a class that skips the negative control is exactly the move this check exists to
    refuse, so there is no reason to exempt it."""
    if not (base and head and HEX40_RE.match(str(base)) and HEX40_RE.match(str(head))):
        return None, ("base_sha and head_sha must both be pinned 40-hex commits before the class "
                      "claim can be measured against the change")
    code, out = _git(["diff", "--name-only", "-z", f"{base}..{head}"])
    if code != 0:
        return None, "cannot diff base_sha..head_sha, so the class claim cannot be measured"
    # -z: a filename containing a newline must not split into phantom paths (#382)
    changed = [p for p in out.split("\0") if p]
    return [p for p in changed if Path(p).suffix.lower() not in _PROSE_SUFFIXES], None


def _changed_paths(base, head, nc_command=None):
    """Paths changed in base..head, split into (production, test/oracle inputs, err).

    This is the denominator the control must live inside. `negative_control.paths` naming anything
    outside it is a DECOY: the control reverts a file the unit never touched, the bound command goes
    RED for a reason unrelated to the change, and the gate reads that as a kill. Lipsitch et al.
    2010 call this a violation of U-comparability — the control differs from head in more than the
    causal variable under test (docs/reviews/2026-09-11 §4 A13; #280)."""
    if not (base and head and HEX40_RE.match(str(base)) and HEX40_RE.match(str(head))):
        return None, None, ("the control cannot be bound to the change without pinned 40-hex "
                            "base_sha and head_sha")
    # --no-renames: a rename changes BOTH paths, and the sealed control is listed the same way, so
    # restoring a renamed file's old name is bound like any other change (2026-10-23 review, P1-2).
    code, out = _git(["diff", "--name-only", "--no-renames", "-z", f"{base}..{head}"])
    if code != 0:
        return None, None, ("cannot diff base_sha..head_sha to bind the control to the change; "
                            "fail-closed")
    changed = [p for p in out.split("\0") if p]  # -z: newline-safe (#382)
    prod, tests = [], []
    for path in changed:
        verdict = _is_oracle_path(path, nc_command, head)
        if verdict is None:
            return None, None, _classifier_unavailable(nc_command, head)
        (tests if verdict else prod).append(path)
    return prod, tests, None


def _command_oracle_paths(command):
    """Protect explicitly named proof inputs and Python module entrypoints, not worker hints."""
    argv = shlex.split(command) if command else []
    if not argv:
        return set()
    inputs = argv[:1]
    # Only one transparent env wrapper and optional --. Environment assignments, cwd changes
    # and command splitting can redirect executable inputs, so require a different grammar.
    if Path(argv[0]).name == "env":
        argv = argv[1:]
        if argv[:1] == ["--"]:
            argv = argv[1:]
        if not argv or argv[0].startswith("-") or "=" in argv[0]:
            return None
        inputs.append(argv[0])
    program = Path(argv[0]).name
    python = re.fullmatch(r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?", program)
    interpreter = python or bool(
        re.fullmatch(
            r"(?:sh|bash|dash|zsh|ksh|mksh|pdksh|yash|posh|ash|node(?:js)?|ruby|perl|php|lua(?:jit)?|Rscript)(?:[-.]?\d+(?:\.\d+)*)?",
            program,
        )
    )
    module = None
    # Where the sweep below starts: the option list it reads belongs to the program, and for an
    # interpreter that is the SCRIPT, whose arguments begin after the script name.
    scan_from = 1
    if interpreter:
        i = 1
        while python and i < len(argv) and argv[i] in {
                "-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-u", "-q"}:
            i += 1
        if i >= len(argv):
            return None
        arg = argv[i]
        if python and arg.startswith("-m"):
            name = (argv[i + 1] if i + 1 < len(argv) else "") if arg == "-m" else arg[2:]
            if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", name):
                return None
            mod_root = name.split(".", 1)[0]
            if mod_root != "unittest" and (
                mod_root in getattr(sys, "stdlib_module_names", ())
                or mod_root in sys.builtin_module_names
                or mod_root in {"pip", "setuptools", "wheel", "virtualenv", "nox", "tox", "coverage", "ipython", "IPython"}
            ):
                return None
            if name not in ("pytest", "unittest") and "-I" in argv[1:i]:
                return None
            module = name.replace(".", "/")
            scan_from = i + 2 if arg == "-m" else i + 1
            # -c is pytest's config option, not the interpreter's. Leaving program
            # as python3 left `python3 -m pytest -c custom.ini` classifying the
            # config as production, so a config-only revert could fake RED.
            if name == "pytest":
                program = "pytest"
        else:
            if arg == "--":
                i += 1
            if i >= len(argv) or argv[i].startswith("-"):
                return None  # inline programs, preload options and stdin are not parsed
            if program.startswith("node") and argv[i] in ("inspect", "debug"):
                return None
            inputs.append(argv[i])
            scan_from = i + 1
    elif program in {"make", "gmake"}:
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in ("-f", "--file", "--makefile") and i + 1 < len(argv):
                i += 1
                inputs.append(argv[i])
            elif arg.startswith(("--file=", "--makefile=")):
                inputs.append(arg.split("=", 1)[1])
            elif arg.startswith("-f") and len(arg) > 2:
                inputs.append(arg[2:])
            elif arg.startswith("-") or "=" in arg:
                return None
            i += 1
    elif program not in {"grep", "pytest"}:
        return None
    # Explicit configuration is executable proof input. Data subjects (e.g. grep operands)
    # remain mutable. Arbitrary transitive dependencies are outside this bounded grammar.
    #
    # A short option is program-specific and may carry its value in the SAME token. One shared
    # set read neither fact: `pytest -c custom.ini` names a config file that went unread, and
    # `grep -fpatterns.txt` names its pattern file with no space, so both fell through to the
    # ordinary classifier as production and a revert control could turn the proof RED by
    # changing the proof itself (PR #323 review, P1). `grep -c` is a counting flag taking no
    # value at all, which is why this cannot simply be one longer list.
    value_opts = ("-f",) + {"pytest": ("-c",)}.get(program, ())
    long_opts = ("--config", "--config-file", "--file")
    i = scan_from
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            # POSIX: everything after is an operand however much it looks like an option, so
            # `grep -- -f patterns.txt` names two files to search, not a pattern file. Reading
            # -f there marked a data subject as an oracle input and rejected the valid negative
            # control that mutation-tested it (PR #323 review, P1).
            break
        if arg.startswith(tuple(opt + "=" for opt in long_opts)):
            inputs.append(arg.split("=", 1)[1])
        elif arg in long_opts and i + 1 < len(argv):
            i += 1
            inputs.append(argv[i])
        elif arg in value_opts and i + 1 < len(argv):
            i += 1
            inputs.append(argv[i])
        elif arg.startswith(value_opts) and len(arg) > 2:
            inputs.append(arg[2:])
        elif len(arg) > 1 and arg[0] == "-" and arg[1] != "-" and any(
                opt[1] in arg[1:] for opt in value_opts):
            # A cluster (-vf x) or a dangling one (-f). The value is not where this can read
            # it, and guessing wrong leaves a proof input mutable; refuse the command instead.
            return None
        i += 1
    paths = set()
    for value in inputs:
        candidate = Path(os.path.normpath(value))
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(_toplevel())
            except (TypeError, ValueError):
                continue
        paths.add(candidate.as_posix())
    if module:
        mod_parts = module.split("/")
        for k in range(1, len(mod_parts) + 1):
            prefix = "/".join(mod_parts[:k])
            paths.update((prefix + ".py", prefix + "/__init__.py"))
        paths.add(module + "/__main__.py")
    return paths


def _classifier_unavailable(nc_command, head=None):
    """Name which of the fail-closed causes actually applies.

    `_is_oracle_path` answers None for three unrelated reasons: the proof command is outside the
    bounded grammar, the runners' discovery configuration at head_sha could not be read, or
    diff_scope.py — the repo's one definition of a test path — could not be loaded beside this
    script. One message for all of them told an operator nothing about which to fix, and an
    installed bundle missing diff_scope.py reported a proof-command problem it did not have
    (#322 bundle oracle vs #323 wrapped-proof grammar).
    """
    if _command_oracle_paths(nc_command) is None:
        return "unsupported proof command; fail-closed"
    found = _is_oracle_path.discovery.get((_ROOTS["git"], os.getcwd(), head, nc_command))
    if found is not None and found[1]:
        return found[1]
    return ("diff_scope.py could not be loaded, so a test path cannot be told from a production "
            "one; fail-closed")


def _is_oracle_path(path, nc_command=None, head=None):
    """Test modules and runner configuration are part of the oracle, never mutation targets.

    A NAME test alone (fixed config names, diff_scope's TESTS regex, the inputs the bound command
    names as options) classed a test the runner collects under any other name as production:
    `checks/add_check.py` under pytest's `python_files = *_check.py` could be reverted, and the
    RED came from the OLD oracle failing against head (2026-10-23 review, P2-1). So with `head`
    the runners' own discovery at head_sha decides too (`discover` below, read once per run):
    pytest's python_files/testpaths from the pytest.ini / pyproject.toml / tox.ini / setup.cfg at
    the root and above each operand, a `-c` file and `-o` overrides; every test path the bound
    pytest/unittest command names as an operand (a `.py` operand, a `file::node` id, a dotted
    unittest module) and unittest's discover pattern; and Jest's testMatch/testRegex from the
    root package.json. Configuration that cannot be read or parsed is None, fail-closed. Still
    outside this bounded grammar, as before: a conftest collection hook, a JS config file
    (jest.config.js, vitest.config.ts) and transitive imports — the coordinator chooses the
    command, and a broad one is its risk to take."""
    if Path(path).name.lower() in {"conftest.py", "pytest.ini", "tox.ini", "setup.cfg",
                                   "pyproject.toml", "package.json", ".coveragerc",
                                   "makefile", "gnumakefile"}:
        return True
    if re.search(r"(?:^|/)(?:jest|vitest|playwright|cypress|karma)\.config\.", path.lower()):
        return True
    inputs = _command_oracle_paths(nc_command)
    if inputs is None:
        return None
    if Path(path).suffix.lower() == ".mk" or Path(path).as_posix() in inputs:
        return True

    def rel(value):
        """A command operand as a repo-relative POSIX path, or None when it leaves the repo."""
        p = os.path.normpath(value.split("::", 1)[0])
        if os.path.isabs(p):
            try:
                p = os.path.relpath(p, _toplevel() or "/")
            except ValueError:
                return None
        p = Path(p).as_posix()
        return None if p == ".." or p.startswith("../") else ("" if p == "." else p)

    def words(value):
        if isinstance(value, list):
            return [str(v) for v in value]
        try:
            return shlex.split(str(value))
        except ValueError:
            return str(value).split()

    def glob_re(glob):
        """A Jest/micromatch glob as a regex body: **, *, ?, {a,b}, [..] and the extglobs
        ?( ) *( ) +( ) @( ); !( ) over-matches one segment, the fail-closed direction."""
        out, i = "", 0
        while i < len(glob):
            ch = glob[i]
            if glob.startswith("**/", i):
                out, i = out + "(?:.*/)?", i + 3
            elif glob.startswith("**", i):
                out, i = out + ".*", i + 2
            elif ch in "?*+@!" and glob[i + 1:i + 2] == "(":
                depth, j, alts, start = 0, i + 1, [], i + 2
                while j < len(glob):
                    depth += {"(": 1, ")": -1}.get(glob[j], 0)
                    if depth == 1 and glob[j] == "|":
                        alts, start = alts + [glob[start:j]], j + 1
                    if depth == 0:
                        break
                    j += 1
                if depth:
                    raise ValueError(f"unbalanced extglob in {glob!r}")
                body = "[^/]*" if ch == "!" else "|".join(glob_re(a) for a in alts + [glob[start:j]])
                out += f"(?:{body})" + {"?": "?", "*": "*", "+": "+"}.get(ch, "")
                i = j + 1
            elif ch == "{" and "}" in glob[i:]:
                j = glob.index("}", i)
                out += "(?:" + "|".join(glob_re(a) for a in glob[i + 1:j].split(",")) + ")"
                i = j + 1
            elif ch == "[" and "]" in glob[i + 1:]:
                j = glob.index("]", i + 1)
                out += "[" + glob[i + 1:j].replace("!", "^", 1).replace("\\", "\\\\") + "]"
                i = j + 1
            else:
                out += {"*": "[^/]*", "?": "[^/]"}.get(ch) or re.escape(ch)
                i += 1
        return out

    def toml_pytest(text):
        """The pytest tables of a pyproject.toml: [tool.pytest.ini_options] and pytest 9's
        [tool.pytest]. tomllib where the interpreter has it (3.11+). Without it — verify-gate.sh
        runs whatever python3 is first on PATH, the system 3.9 on macOS — a scan of the two keys
        this reads, and a key it cannot read there is a refusal, never a silent miss."""
        try:
            import tomllib
        except ImportError:
            tomllib = None
        if tomllib is not None:
            tool = tomllib.loads(text).get("tool", {}).get("pytest", {})
            return [tool.get("ini_options", {}), tool]
        found, inside, lines, i = {}, False, text.splitlines(), 0
        while i < len(lines):
            line = lines[i].split("#", 1)[0].strip()
            if line.startswith("["):
                inside = line.replace(" ", "") in ("[tool.pytest.ini_options]", "[tool.pytest]")
            hit = re.match(r"(python_files|testpaths)\s*=\s*(.*)", line) if inside else None
            if hit:
                value = hit.group(2)
                while value.count("[") > value.count("]") and i + 1 < len(lines):
                    i += 1
                    value += " " + lines[i].split("#", 1)[0].strip()
                quoted = [a or b for a, b in re.findall(r'"([^"]*)"|\'([^\']*)\'', value)]
                found[hit.group(1)] = quoted if value.startswith("[") else " ".join(quoted)
            i += 1
        if re.search(r"\b(?:python_files|testpaths)\b", text) and not found:
            raise ValueError("python_files/testpaths present in a form this interpreter cannot "
                             "read without tomllib")
        return [found]

    def discover(command):
        """(matcher, None) or (None, reason): what the runners collect as tests at head_sha."""
        argv = shlex.split(command) if command else []
        if argv and Path(argv[0]).name == "env":
            argv = argv[2:] if argv[1:2] == ["--"] else argv[1:]
        prog = Path(argv[0]).name if argv else ""
        runner, rest = ("pytest", argv[1:]) if prog == "pytest" else (None, [])
        if re.fullmatch(r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?", prog):
            i = 1
            while i < len(argv) and argv[i] in {"-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-u", "-q"}:
                i += 1
            arg = argv[i] if i < len(argv) else ""
            name = (argv[i + 1] if i + 1 < len(argv) else "") if arg == "-m" else arg[2:]
            if arg.startswith("-m") and name in ("pytest", "unittest"):
                runner, rest = name, argv[i + (2 if arg == "-m" else 1):]
        # Operands are read generously: an option value this grammar does not know becomes one
        # more operand, which only ADDS a path or a root — never narrows what counts as a test.
        ops, configs, overrides, opt = [], [], {}, {}
        valued = {"pytest": {"-c": "c", "--config-file": "c", "-o": "o", "--override-ini": "o",
                             "--rootdir": "", "-k": "", "-m": "", "-p": ""},
                  "unittest": {"-p": "p", "--pattern": "p", "-s": "s", "--start-directory": "s",
                               "-t": "", "--top-level-directory": "", "-k": ""}}.get(runner, {})
        i, after = 0, False
        while i < len(rest):
            tok = rest[i]
            long_key, eq, long_val = tok.partition("=")
            if after or not tok.startswith("-"):
                ops.append(tok)
            elif tok == "--":
                after = True
            elif tok in valued:
                opt.setdefault(valued[tok], []).append(rest[i + 1] if i + 1 < len(rest) else "")
                i += 1
            elif eq and long_key in valued and tok.startswith("--"):
                opt.setdefault(valued[long_key], []).append(long_val)
            elif runner == "pytest" and tok[:2] in ("-c", "-o") and len(tok) > 2:
                opt.setdefault(tok[1], []).append(tok[2:])
            i += 1
        configs = opt.get("c", [])
        for pair in opt.get("o", []):
            key, _, val = pair.partition("=")
            overrides.setdefault(key.strip(), []).extend(words(val))
        exact, dirs, roots = set(), {""}, []
        if runner == "unittest" and ops[:1] == ["discover"]:
            opt.setdefault("s", []).extend(ops[1:2])  # discover's positionals: start, pattern
            opt.setdefault("p", []).extend(ops[2:3])
        elif runner == "unittest":
            for op in ops:
                if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", op):
                    # A dotted operand names a module, a class or a method
                    # (`checks.add_check.TestAdd.test_add`): the oracle is the deepest prefix that
                    # is a module at head_sha, not the whole dotted path read as a file. With no
                    # prefix resolvable, every prefix stays protected (PR #631 review, P1).
                    parts = op.split(".")
                    cands = [f"{'/'.join(parts[:k])}{tail}"
                             for k in range(1, len(parts) + 1) for tail in (".py", "/__init__.py")]
                    code, found = _git(["--literal-pathspecs", "ls-tree", "--full-tree", "-r", "-z",
                                        "--name-only", str(head), "--", *cands])
                    if code != 0:
                        return None, (f"cannot resolve the unittest operand {op!r} at head_sha "
                                      f"{head}; fail-closed (PR #631 review, P1)")
                    present = [c for c in cands if c in set(found.split("\0"))]
                    exact.update(present[-1:] or cands)
                elif rel(op):
                    exact.add(rel(op))
        else:
            for p in (q for q in map(rel, ops) if q is not None):
                roots.append(p)  # "" (an operand of `.`) roots the whole repo
                if p:
                    exact.add(p)
                    parts = p.split("/")
                    dirs.update("/".join(parts[:k]) for k in range(len(parts)))
        names = ("pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")
        wanted = {f"{d}/{n}".lstrip("/") for d in dirs for n in names} | {"package.json"}
        wanted |= set(filter(None, map(rel, configs)))
        code, listing = _git(["--literal-pathspecs", "ls-tree", "--full-tree", "-r", "-z",
                              "--name-only", str(head), "--", *sorted(wanted)])
        if code != 0:
            return None, (f"cannot list the test-discovery configuration at head_sha {head}; "
                          "fail-closed (2026-10-23 review, P2-1)")
        py_globs, testpaths, regexes = list(overrides.get("python_files", [])), [], []
        testpaths += [p for p in map(rel, overrides.get("testpaths", [])) if p is not None]
        for cfg in sorted(p for p in listing.split("\0") if p):
            code, raw, _ = _git_bytes(["cat-file", "blob", f"{head}:{cfg}"])
            try:
                if code != 0:
                    raise ValueError("unreadable at head_sha")
                text = raw.decode("utf-8")
                if cfg == "package.json":
                    jest = json.loads(text).get("jest")
                    jest = jest if isinstance(jest, dict) else {}
                    rx = jest.get("testRegex") or []
                    regexes += [re.compile(r) for r in ([rx] if isinstance(rx, str) else rx)]
                    regexes += [re.compile("^/" + glob_re(g.replace("<rootDir>/", "")) + "$")
                                for g in words(jest.get("testMatch") or []) if not g.startswith("!")]
                    continue
                if cfg.endswith(".toml"):
                    sections = toml_pytest(text)
                else:
                    parser = configparser.RawConfigParser(strict=False, allow_no_value=True)
                    parser.read_string(text)
                    sections = [dict(parser[s]) for s in ("pytest", "tool:pytest")
                                if parser.has_section(s)]
                for sec in sections:
                    py_globs += words(sec.get("python_files") or [])
                    testpaths += [p for p in (rel(posixpath.join(cfg.rpartition("/")[0], t))
                                              for t in words(sec.get("testpaths") or []))
                                  if p is not None]
            except (ValueError, TypeError, AttributeError, re.error, configparser.Error) as exc:
                return None, (f"the test-discovery configuration {cfg} at head_sha cannot be read "
                              f"({exc}), so a test path cannot be told from a production one; "
                              "fail-closed (2026-10-23 review, P2-1)")
        # Union, never a narrowing: the operands' trees AND testpaths (pytest ignores testpaths
        # when given operands; reading both only ever protects more), else the whole repo.
        py_roots = roots + testpaths if testpaths else [""]
        py_globs = py_globs or ["test_*.py", "*_test.py"]
        ut_globs = (opt.get("p") or ["test*.py"]) if runner == "unittest" else []
        ut_roots = [p for p in map(rel, opt.get("s") or ["."]) if p is not None]

        def under(p, tops):
            anc = ["/".join(p.split("/")[:k]) for k in range(1, p.count("/") + 1)]
            return any(t == "" or p == t or any(fnmatch.fnmatchcase(a, t) for a in anc) for t in tops)

        def collected(p, globs):
            leaf = p.rpartition("/")[2]
            return any(fnmatch.fnmatchcase(p, g) or fnmatch.fnmatchcase(p, "*/" + g) if "/" in g
                       else fnmatch.fnmatchcase(leaf, g) for g in globs)

        def matcher(p):
            return (p in exact
                    or (p.endswith(".py") and under(p, py_roots) and collected(p, py_globs))
                    or (p.endswith(".py") and under(p, ut_roots) and collected(p, ut_globs))
                    or any(r.search("/" + p) for r in regexes))
        return matcher, None

    if head is not None:
        key = (_ROOTS["git"], os.getcwd(), head, nc_command)
        if key not in _is_oracle_path.discovery:
            _is_oracle_path.discovery[key] = discover(nc_command)
        matcher, _err = _is_oracle_path.discovery[key]
        if matcher is None:
            return None
        if matcher(Path(path).as_posix()):
            return True
    return _is_test_path(path)


# (git root, cwd, head_sha, nc_command) -> (matcher | None, reason): the runners' discovery at
# head_sha, read once per run before any control executes (main() clears it per run).
_is_oracle_path.discovery = {}


def _bind_paths_to_change(paths, m, what, nc_command=None):
    """Every path the control touches must be a PRODUCTION path this unit actually changed.
    Returns an error string or None."""
    prod, _tests, err = _changed_paths(m.get("base_sha"), m.get("head_sha"), nc_command)
    if err:
        return err
    scope = getattr(m, "oracle_scope", None)
    prod_set = set(scope["paths"]) if scope else set(prod)
    for path in paths:
        norm = Path(path).as_posix()
        verdict = _is_oracle_path(norm, nc_command, m.get("head_sha"))
        if verdict is None:
            return _classifier_unavailable(nc_command, m.get("head_sha"))
        if verdict:
            return (f"{what} names {path!r}, which is a TEST path. Reverting the test that encodes "
                    "the criterion makes the proof go RED because the oracle is gone, not because "
                    "the behaviour came back — the control must revert the BEHAVIOUR (#280)")
        if norm in prod_set:
            continue
        return (f"{what} names {path!r}, which base_sha..head_sha does not change. A control that "
                "reverts a file this unit never touched is a decoy: its RED says nothing about the "
                f"change being proved. Production paths changed here: {sorted(prod_set) or 'none'} "
                "(#280)")
    return None


def check_oracle_scope(m, source, digest):
    """Optional exception owned by the digest-bound coordinator contract, never the manifest.

    Exact commit pair, artifact bytes, criterion IDs and line coordinates are mandatory. This
    authorizes a reviewed hand control for test-only characterization or documentation work;
    ordinary mutations retain their changed-production binding.
    """
    if not (source and digest):
        return []  # check_scope already refuses a manifest with no authoritative contract
    raw, err = read_source(source)
    if err or sha256_of(raw) != _norm_digest(digest):
        return ["oracle scope: authoritative contract unreadable or digest mismatch"]
    try:
        doc = json_contract(raw.decode("utf-8"))
    except ValueError as exc:  # check_scope names the same defect; never an exception (review P3)
        return [f"oracle scope: {exc}"]
    scope = doc.get("oracle_scope") if doc else None
    if scope is None:
        return []
    if not isinstance(scope, dict) or scope.get("kind") not in ("characterization", "documentation"):
        return ["oracle scope: kind must be characterization or documentation"]
    if any(scope.get(k) != m.get(k) for k in ("base_sha", "head_sha")):
        return ["oracle scope: authorized commit pair differs from the manifest"]
    ids = scope.get("criterion_ids")
    if not (isinstance(ids, list) and ids and all(isinstance(x, str) for x in ids)) \
            or set(ids) != set(doc["criterion_ids"]):  # strings only: no TypeError (review P3)
        return ["oracle scope: must bind every criterion in this unit's contract"]
    paths = scope.get("paths")
    if not isinstance(paths, dict) or not paths:
        return ["oracle scope: explicit path/line coordinates required"]
    for path, lines in paths.items():
        _, err = _resolve(path)
        if err or _is_oracle_path(path, head=m.get("head_sha")) is not False:
            return ["oracle scope: TEST paths and escaping paths cannot be mutated"]
        if not isinstance(lines, list) or not lines or any(type(n) is not int or n < 1 for n in lines):
            return ["oracle scope: positive integer line coordinates required"]
        if _git(["cat-file", "-e", f"{m['head_sha']}:{path}"])[0] != 0:
            return ["oracle scope: target must exist at head_sha"]
    prod, tests, err = _changed_paths(m.get("base_sha"), m.get("head_sha"))
    if err:
        return [f"oracle scope: {err}"]
    if any(_is_test_path(p) is not True and Path(p).suffix.lower() not in _PROSE_SUFFIXES
           for p in prod + tests):
        return ["oracle scope: this unit changes production code; default mutation binding required"]
    if scope["kind"] == "characterization" and not tests:
        return ["oracle scope: characterization must change a test"]
    if scope["kind"] == "documentation" and (tests or not prod):
        return ["oracle scope: documentation must change prose only"]
    nc = m.get("negative_control") or {}
    content, err = read_artifact(m, nc.get("artifact"))
    if nc.get("tool") != "hand" or err:
        return ["oracle scope: requires a pinned hand-mutant artifact"]
    if hashlib.sha256(content).hexdigest() != scope.get("artifact_sha256"):
        return ["oracle scope: mutant artifact differs from coordinator authorization"]
    diff = _extract_diff(content.decode("utf-8", "replace"))
    if not diff or set(_diff_target_paths(diff)) != set(paths):
        return ["oracle scope: every mutant path must match the authorized path set"]
    touched = _hunk_lines(diff, "-")
    if set(touched) != set(paths) or any(not touched[p] or not touched[p] <= set(paths[p]) for p in paths):
        return ["oracle scope: mutant coordinates exceed coordinator authorization"]
    m.oracle_scope = scope
    return []


def _diff_records(diff):
    """One hunk-state grammar for both endpoint inventory and edited coordinates."""
    # split("\n"), never splitlines(): the latter also splits on \r, form feeds and Unicode
    # separators INSIDE a content line, which miscounts the hunk — diffparse.py's grammar, which
    # this is one copy of (2026-10-26 review). A trailing newline yields one empty tail line.
    old_left = new_left = 0
    lines = diff.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if line == r"\ No newline at end of file":
            continue
        if old_left or new_left:
            kind = line[:1]
            if kind not in ("-", "+", " "):
                raise ValueError("incomplete diff hunk")
            old_left -= kind in ("-", " ")
            new_left -= kind in ("+", " ")
            if old_left < 0 or new_left < 0:
                raise ValueError("diff hunk exceeds declared line counts")
        elif line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("malformed hunk header")
            _, ac, _, bc = match.groups()
            old_left, new_left = int(ac or 1), int(bc or 1)
            kind = "hunk"
        else:
            kind = "header"
        yield kind, line
    if old_left or new_left:
        raise ValueError("incomplete diff hunk")


def _diff_target_paths(diff):
    return sorted(set(_iter_diff_target_paths(diff)))


def _iter_diff_target_paths(diff):
    """Inventory both endpoints, including metadata-only changes and deleted files.

    Ambiguous quoted/space-containing headers fail closed rather than disappearing from scope.
    """
    for kind, line in _diff_records(diff):
        if kind != "header":
            continue
        prefixed = True
        if line.startswith("diff --git "):
            values = shlex.split(line[11:])
            if len(values) != 2:
                raise ValueError("ambiguous diff path header")
        elif line.startswith(("--- ", "+++ ")):
            values = [line[4:].split("\t")[0]]
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            values = [line.split(" ", 2)[2]]
            prefixed = False
        else:
            continue
        for value in values:
            if value == "/dev/null":
                continue
            if value.startswith('"') or "\\" in value:
                raise ValueError("quoted diff paths are not supported; use an unambiguous patch")
            if prefixed and value.startswith(("a/", "b/")):
                value = value[2:]
            _, err = _resolve(value)
            if err or not value or value.startswith("-"):
                raise ValueError(f"invalid diff path: {value!r}")
            yield value


# The control-outcome reader lives in runtime/scripts/_verify_sig.py (RV-D2);
# this module keeps a single re-export — the one seam name its callers read.
_sig_spec = importlib.util.spec_from_file_location(
    "_verify_sig", Path(__file__).resolve().parent / "_verify_sig.py")
_verify_sig = importlib.util.module_from_spec(_sig_spec)
_sig_spec.loader.exec_module(_verify_sig)
_failure_signature = _verify_sig._failure_signature
# _counted stays reachable for the same reason: the RV-C2 characterization net
# pins its contract directly, and a pinned seam function is interface, not detail.
_counted = _verify_sig._counted


def _hunk_lines(text, side):
    """Actual edited coordinates, never context. Half-integers identify insertion seams.

    The old side of a mutant and new side of base..head both use head coordinates.
    A replacement binds its removed lines; a pure insertion binds the gap before the next line.
    """
    out, current, old_path = {}, None, None
    old = new = None
    removed, added = [], []

    def flush():
        if current and (removed or added):
            own, other = (removed, added) if side == "-" else (added, removed)
            out.setdefault(current, set()).update(own or [other[0][1] - 0.5])
        removed.clear()
        added.clear()

    for kind, line in _diff_records(text):
        if kind == "header" and line.startswith("diff --git "):
            flush()
            old = new = None
            current = None
        elif kind == "header" and line.startswith("--- "):
            old_path = line[4:].split("\t")[0]
        elif kind == "header" and line.startswith("+++ "):
            flush()
            target = old_path if side == "-" else line[4:].split("\t")[0]
            current = target[2:] if target and target.startswith(("a/", "b/")) else target
            if current and current != "/dev/null":
                out.setdefault(current, set())
        elif kind == "hunk":
            flush()
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("malformed hunk header")
            a, ac, b, bc = match.groups()
            old, new = int(a) + (ac == "0"), int(b) + (bc == "0")
        elif kind == "-":
            removed.append((old, new))
            old += 1
        elif kind == "+":
            added.append((new, old))
            new += 1
        elif kind == " ":
            flush()
            old += 1
            new += 1
    flush()
    # Strip the opposite-side coordinate retained for pure insertion/deletion seams.
    return {path: {x[0] if isinstance(x, tuple) else x for x in lines}
            for path, lines in out.items() if path != "/dev/null"}


def _bind_hunks_to_change(diff, m):
    """A `hand` mutant must touch the lines this unit changed, not merely the same FILE.

    Binding by path alone left a decoy one level down: a production file can carry the criterion
    change AND an unrelated change, and a mutant that only touches the unrelated hunk still goes
    RED under a broad test command while the criterion behaviour stands untouched (PR #308 review).
    """
    base, head = m.get("base_sha"), m.get("head_sha")
    if not (base and head and HEX40_RE.match(str(base)) and HEX40_RE.match(str(head))):
        return "the hand mutant cannot be bound to the change without pinned base_sha and head_sha"
    touched = _hunk_lines(diff, "-")
    if set(_diff_target_paths(diff)) != set(touched):
        return "the hand mutant has a deleted, renamed or mode-only path without bound hunks"
    for path, lines in touched.items():
        code, out = _git(["--literal-pathspecs", "diff", "--no-ext-diff", "--no-textconv",
                          "--no-renames", "-U0", f"{base}..{head}", "--", path])
        if code != 0:
            return (f"cannot diff {path} over base_sha..head_sha to bind the hand mutant to the "
                    "change; fail-closed")
        scope = getattr(m, "oracle_scope", None)
        changed = (set(scope["paths"].get(path, [])) if scope else
                   _hunk_lines(out, "+").get(path, set()))
        if not lines:
            return (f"the hand mutant's diff names {path} but carries no hunk for it, so nothing "
                    "says which behaviour it mutates (#280)")
        allowed = changed | {n + offset for n in changed if isinstance(n, int)
                             for offset in (-0.5, 0.5)}
        if not lines <= allowed:
            return (f"the hand mutant touches {path} at line(s) {sorted(lines)[:6]}, and "
                    f"base_sha..head_sha changes line(s) {sorted(changed)[:6] or 'none'} there — "
                    "they do not overlap completely. Mutating an untouched hunk of a changed file is the same "
                    "decoy as mutating an untouched file: the RED comes from behaviour this unit "
                    "did not introduce (#280)")
    return None


def _nc_paths(nc):
    """`negative_control.paths` — the production paths the revert control restores to base_sha.
    Repo-relative, inside the toplevel, never option-like. Returns (paths, err)."""
    raw = nc.get("paths")
    if raw is None:
        return None, None
    if not (isinstance(raw, list) and raw and all(isinstance(x, str) and x for x in raw)):
        return None, "negative_control.paths must be a non-empty list of repo-relative path strings"
    for path in raw:
        if path.startswith("-"):
            return None, f"refusing option-like path in negative_control.paths: {path}"
        _, err = _resolve(path)
        if err:
            return None, f"negative_control.paths: {err}"
    return raw, None


def _extract_diff(text):
    """Pull the unified diff out of a `hand` NC artifact. The diff runs from the first `diff --git`
    or `--- ` header through the last line that still looks like diff body; trailing prose (the
    test output that shows the RED) is dropped."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if ln.startswith("diff --git ") or ln.startswith("--- ")), None)
    if start is None:
        return None
    end = start
    for i in range(start, len(lines)):
        ln = lines[i]
        if (ln.startswith(("diff --git ", "index ", "--- ", "+++ ", "@@", "+", "-", " ",
                           "new file mode", "deleted file mode", "similarity index",
                           "rename from", "rename to", "old mode", "new mode"))
                or ln == ""):
            end = i
        else:
            break
    body = "\n".join(lines[start:end + 1]).rstrip("\n")
    return (body + "\n") if body.strip() else None


def _apply_control(wt, m, nc, tool, nc_command=None):
    """Apply the negative control inside the throwaway worktree `wt`. Returns an error string or
    None. Fail-closed on every git error: a control that did not apply is not a control."""
    # #629: checkout/revert/apply below materialise worker content and would run a repo-config
    # clean/smudge filter a .gitattributes selects. In the executed control `wt` runs against the
    # verifier's own git dir (_Authority.control_git_dir), whose config defines no driver, so none
    # runs however late the source's config gained it (W4 custody sweep). Each call still blanks
    # every driver `wt`'s config declares, read in `wt` itself immediately before the call (PR
    # #649 review: the same directory and ref state as the git call that could run them).
    if tool == "revert":
        base = m.get("base_sha")
        paths, err = _nc_paths(nc)
        if err:
            return err
        if paths:
            if not (base and HEX40_RE.match(str(base))):
                return ("negative_control.paths needs a pinned 40-hex base_sha to restore the "
                        "pre-fix content from")
            bind_err = _bind_paths_to_change(paths, m, "negative_control.paths", nc_command)
            if bind_err:
                return bind_err
            code, _, gerr = _run_at(wt, [_Authority.git_bin(), "--literal-pathspecs",
                                         "checkout", str(base), "--", *paths],
                                    env=_Authority.blanked_env(_Authority.driver_blanks(wt)))
            if code != 0:
                return f"could not restore {paths} from base_sha in the control worktree: {gerr.strip()}"
            # --cached: the INDEX is what _seal_control's write-tree commits, so the check reads
            # that object, never the work tree beside it (2026-10-23 review, P1-2).
            code, actual, gerr = _run_at(wt, [_Authority.git_bin(), "diff", "--cached", "--name-only",
                                            "--no-renames", "-z", "HEAD"], env=_Authority.git_env())
            if code != 0:
                return f"cannot inspect restored paths: {gerr.strip()}"
            affected = set(actual.rstrip('\0').split('\0')) if actual else set()
            if affected != set(paths):
                return f"restored paths {sorted(affected)} differ from declared paths {sorted(paths)}"
            return _bind_paths_to_change(affected, m, "the applied revert", nc_command)
        # No paths: the ONLY sound fallback is reverting the whole linear base..head range.
        head = m.get("head_sha")
        if not (base and head and HEX40_RE.match(str(base)) and HEX40_RE.match(str(head))):
            return ("negative_control.paths is required for tool 'revert' (the range fallback needs "
                    "pinned base_sha and head_sha)")
        if _run_at(wt, [_Authority.git_bin(), "merge-base", "--is-ancestor", str(base), str(head)],
                   env=_Authority.git_env())[0] != 0:
            return ("negative_control.paths is required: base_sha..head_sha is not linear "
                    "(base is not an ancestor of head), so a range revert is not well-defined")
        code, merges, _ = _run_at(wt, [_Authority.git_bin(), "rev-list", "--merges", f"{base}..{head}"],
                                  env=_Authority.git_env())
        if code != 0 or merges.strip():
            return ("negative_control.paths is required: base_sha..head_sha contains merge commits, "
                    "so a range revert is not well-defined")
        # A range revert takes the TESTS with it. When the unit adds a test module, reverting the
        # range deletes it, and the bound command then fails because the test file is gone — a
        # missing oracle reads as a kill. Refuse, and make the unit name its production paths
        # (docs/reviews/2026-09-11 §4 A14b/A21; #280).
        _prod, tests, bind_err = _changed_paths(base, head, nc_command)
        if bind_err:
            return bind_err
        if tests:
            return ("negative_control.paths is REQUIRED here: base_sha..head_sha changes test "
                    f"paths ({sorted(tests)}), and a range revert would remove them along with the "
                    "fix. The bound command would then go RED because its oracle is gone, not "
                    "because the behaviour came back. Name the production paths the control should "
                    "restore (#280)")
        code, _, gerr = _run_at(wt, [_Authority.git_bin(), "revert", "--no-commit",
                                     f"{base}..{head}"],
                                timeout=60,
                                env=_Authority.blanked_env(_Authority.driver_blanks(wt)))
        if code != 0:
            return f"git revert of base_sha..head_sha failed in the control worktree: {gerr.strip()}"
        return None
    # tool == "hand": the mutant IS the diff quoted in the artifact — apply exactly that.
    raw, err = read_artifact(m, nc.get("artifact"))
    if err:
        return f"negative_control.artifact unreadable, so the hand mutant cannot be applied: {err}"
    diff = _extract_diff(raw.decode("utf-8", "replace"))
    if not diff:
        return "negative_control.artifact for tool 'hand' quotes no applicable unified diff"
    targets = _diff_target_paths(diff)
    if not targets:
        return ("negative_control.artifact for tool 'hand' quotes a diff with no `+++` target — "
                "nothing identifies which file the mutant touches, so it cannot be bound to the "
                "change (#280)")
    bind_err = _bind_paths_to_change(targets, m, "the hand mutant's diff", nc_command)
    if bind_err:
        return bind_err
    bind_err = _bind_hunks_to_change(diff, m)
    if bind_err:
        return bind_err
    code, _, gerr = _run_at(wt, [_Authority.git_bin(), "apply", "--index",
                                 "--whitespace=nowarn", "-"],
                            stdin_bytes=diff.encode("utf-8"),
                            env=_Authority.blanked_env(_Authority.driver_blanks(wt)))
    if code != 0:
        return ("the hand mutant quoted in negative_control.artifact does not apply at head_sha "
                f"({gerr.strip()}) — the quoted diff is not the diff that was run")
    # Git may relocate contextual hunks. Worker headers therefore cannot establish where the
    # edit landed. Include the index so added/deleted/renamed/mode-only effects cannot disappear.
    code, actual, gerr = _run_at(wt, [_Authority.git_bin(), "diff", "--cached", "--no-ext-diff",
                                    "--no-textconv", "--no-renames", "-U0", "HEAD"], env=_Authority.git_env())
    if code != 0:
        return f"cannot inspect applied mutant coordinates: {gerr.strip()}"
    if (_diff_target_paths(actual) != targets or
            _hunk_lines(actual, "-") != _hunk_lines(diff, "-")):
        return "applied mutant paths/coordinates differ from the quoted control (possible hunk relocation)"
    return (_bind_paths_to_change(_diff_target_paths(actual), m, "the applied hand mutant", nc_command) or
            _bind_hunks_to_change(actual, m))


def execute_negative_control(m, nc_command=None):
    """#255 — EXECUTE the negative control. Returns (executed_ok, messages).

    The proof, not the paperwork. The control is APPLIED at `head_sha` (`revert`: restore
    `negative_control.paths` from base_sha — or, only when no paths are given and the range is
    linear, `git revert --no-commit base..head`; `hand`: `git apply` the unified diff quoted in
    the artifact) and SEALED into a throwaway sibling commit of head_sha (_seal_control). Only
    then does worker code run — three times, each in its own repository under a fresh HOME and
    TMPDIR (_phase_run): CLEAN at head_sha, CONTROL at the sealed mutant, CLEAN at head_sha again.

    The control counts as KILLED only when BOTH clean runs exit 0 and the control run exits
    NON-ZERO with a genuine failure signature. A command that fails under the control but also
    fails clean proves nothing; one that passes under the control is a TAUTOLOGY. The phases are
    indistinguishable by git status, HOME, TMPDIR, a branch ref, or tag type: each repository
    copies the source's ref layout, and every ref that named head_sha names that phase's commit
    instead. An annotated tag stays an annotated tag of that commit, and a tag of a tag stays a
    chain, so `git cat-file -t` agrees with the clean checkout and `HEAD` equals
    `refs/heads/<branch>` in the control run too
    (PR #571 review). The object store is reached through alternates, named in the filesystem
    encoding; a proof that opens that file and reads the source repo is the residual a
    coordinator's clean-env re-run still has to cover.

    Fail-closed everywhere: an unknown tool, a missing command/paths, a git error, a worktree that
    cannot be made, or a control that applies no change at all."""
    def _seal_control(wt, head):
        """Commit the control applied in `wt` as a SIBLING of head_sha. Returns (mutant_sha, err).

        The mutant commit is head_sha's own commit object with only its `tree` line swapped for the
        applied control's tree: same parents, author, committer and message. A control phase run from
        it sees a CLEAN work tree (`git status --porcelain` empty) and the same `HEAD~1`, log and
        identity a clean phase sees — the phase is not distinguishable by git state, only by the
        content under test (review P1). Only the index is read, so untracked residue of the apply
        never reaches the control run.

        The stillborn check lives here and compares TREES: a control whose applied tree equals
        head_sha's tree changed NOTHING and cannot make any proof go RED (#255).

        The bind is re-read HERE, from the tree just written — the very object the control phase
        checks out. _apply_control's checks read the index too, but a check of one object and a
        seal of another left room for anything that staged content between or beside them (a
        post-checkout hook updating the index while the check read the work tree: 2026-10-23
        review, P1-2). Every path the sealed tree changes must be a production path this unit
        changed, or nothing is sealed."""
        git, env = _Authority.git_bin(), _Authority.git_env()
        # #629: a racily-clean index entry (its mtime matching the index's after the control's
        # checkout) is re-hashed by write-tree, which re-runs a selected clean filter — so the
        # driver blanks must ride this call, as they do the checkout that produced the index.
        code, tree, gerr = _run_at(wt, [git, "write-tree"],
                                   env=_Authority.blanked_env(_Authority.driver_blanks(wt)))
        tree = tree.strip()
        if code != 0 or not HEX40_RE.match(tree):
            return None, f"cannot record the applied control's tree: {gerr.strip()}"
        head_tree = _tree(head)
        if tree == head_tree:
            return None, ("the negative control changed NOTHING at head_sha — a no-op mutant cannot "
                          "make any proof go RED (#255)")
        code, sealed, gerr = _run_at(wt, [git, "diff-tree", "-r", "-z", "--name-only", "--no-renames",
                                          str(head_tree), tree], env=env)
        if code != 0:
            return None, f"cannot list what the sealed control changes: {gerr.strip()}"
        bind_err = _bind_paths_to_change([p for p in sealed.split("\0") if p], m,
                                         "the sealed control", nc_command)
        if bind_err:
            return None, bind_err
        code, raw, gerr = _git_bytes(["cat-file", "commit", str(head)])
        if code != 0 or not raw.startswith(b"tree ") or b"\n" not in raw:
            return None, f"cannot read head_sha's commit object to seal the control: {gerr.strip()}"
        sibling = b"tree " + tree.encode("ascii") + raw[raw.index(b"\n"):]
        code, mutant, gerr = _run_at(wt, [git, "hash-object", "-t", "commit", "-w", "--stdin"],
                                     stdin_bytes=sibling, env=env)
        mutant = mutant.strip()
        if code != 0 or not HEX40_RE.match(mutant):
            return None, f"cannot commit the applied control as a throwaway commit: {gerr.strip()}"
        return mutant, None

    def _prepare_control(top, head, m, nc, tool, nc_command):
        """Apply the control in a scratch worktree and seal it (_seal_control) BEFORE any worker code
        runs. Returns (mutant_sha, err). The scratch worktree is removed before the first phase
        executes, so no run can reach it, and the sealed commit is content-addressed, so no run can
        alter what the control phase checks out."""
        holder = tempfile.mkdtemp(prefix="orca-nc-")
        wt = Path(holder) / "wt"
        # #629: populating the worktree from head_sha, restoring base paths, reverting and applying
        # all materialise worker content, which runs any filter (and the revert/apply any merge
        # driver) an attribute selects. Listing the drivers a config declares and blanking them
        # (PR #649) left a window: one the graded worker added to the shared config after the
        # listing ran here (W4 custody sweep). So the scratch worktree is no linked worktree of
        # `top`: its `.git` is a gitfile naming a git dir this verifier builds
        # (_Authority.control_git_dir), whose config defines no driver at all. driver_blanks still
        # reads that config before each call, a belt that keeps the fail-closed refusal.
        custody = None  # entered by hand: only BUILDING it is "could not create" (an OSError)
        try:
            try:
                built = _Authority.control_git_dir(top, head)
                gd = built.__enter__()
                custody = built
                wt.mkdir()
                (wt / ".git").write_bytes(b"gitdir: " + os.fsencode(gd) + b"\n")
            except OSError as err:
                return None, f"could not create the control worktree at head_sha: {err}"
            wt = str(wt)
            code, _, gerr = _run_at(wt, [_Authority.git_bin(), "checkout", "-q", "--detach",
                                         str(head)], timeout=120,
                                    env=_Authority.blanked_env(_Authority.driver_blanks(wt)))
            if code != 0:
                return None, f"could not populate the control worktree at head_sha: {gerr.strip()}"
            apply_err = _apply_control(wt, m, nc, tool, nc_command)
            if apply_err:
                return None, apply_err
            return _seal_control(wt, head)
        finally:
            if custody is not None:
                custody.__exit__(None, None, None)  # removes the control git dir
            shutil.rmtree(holder, ignore_errors=True)

    def _tag_kind(raw):
        """('commit'|'tag', object sha) for an annotated tag, else (None, None)."""
        nl = raw.find(b"\n")
        if nl < 0 or not raw.startswith(b"object "):
            return None, None
        obj = raw[len(b"object "):nl]
        if not HEX40_RE.fullmatch(obj.decode("ascii", "replace")):
            return None, None
        line = raw[nl + 1:].split(b"\n", 1)[0]
        if line == b"type commit":
            return "commit", obj.decode("ascii")
        if line == b"type tag":
            return "tag", obj.decode("ascii")
        return None, None

    def _unsigned_tag(raw):
        """Drop every signature. A `gpgsig` header and a signature appended after the
        message (the v0.7.1 SSH layout, which git's parse_signature cuts at the first
        BEGIN line) both cover the object line, so either one verifies on the clean
        replay and fails only under the control."""
        header, sep, body = raw.partition(b"\n\n")
        kept, skipping = [], False
        for line in header.split(b"\n"):
            if line.startswith(b"gpgsig "):
                skipping = True
                continue
            if skipping and line.startswith(b" "):
                continue
            skipping = False
            kept.append(line)
        marks = (b"-----BEGIN PGP SIGNATURE-----", b"-----BEGIN SSH SIGNATURE-----")
        lines = body.split(b"\n")
        for i, line in enumerate(lines):
            if line.startswith(marks):
                lines = lines[:i]
                break
        body = b"\n".join(lines)
        return b"\n".join(kept) + sep + body

    def _retarget_tag(top, repo, tag_sha, commit, seen=None):
        """A new annotated tag whose target is this phase's commit. A tag of a tag is
        rewritten as a chain, each layer still a tag. Returns (new_sha, err). Replacing
        the tag with the bare commit would make `git cat-file -t` disagree with the
        clean checkout."""
        if seen is None:
            seen = set()
        if tag_sha in seen or len(seen) >= 8:
            return None, "annotated tag chain is cyclic or too deep"
        seen.add(tag_sha)
        git, env = _Authority.git_bin(), _Authority.git_env()
        code, raw, gerr = _run_bytes([git, "-C", top, "cat-file", "tag", tag_sha],
                                    timeout=30, env=env)
        kind, obj = _tag_kind(raw) if code == 0 else (None, None)
        if kind is None:
            return None, gerr.strip() or "not an annotated tag of a commit or a tag"
        raw = _unsigned_tag(raw)
        if kind == "tag":
            obj, err = _retarget_tag(top, repo, obj, commit, seen)
            if err:
                return None, err
        else:
            obj = commit
        nl = raw.find(b"\n")
        if nl < 0 or not raw.startswith(b"object "):
            return None, "annotated tag lost its object line"
        rewritten = b"object " + obj.encode("ascii") + raw[nl:]
        code, new, gerr = _run_at(repo, [git, "hash-object", "-t", "tag", "-w", "--stdin"],
                                  stdin_bytes=rewritten, env=env)
        new = new.strip()
        if code != 0 or not HEX40_RE.match(new):
            return None, gerr.strip() or "could not write the retargeted tag"
        return new, None

    def _stage_phase_repo(top, head, commit, repo, phase):
        """Build `repo` with the source's refs, retargeting any ref that names `head` onto
        `commit`. An annotated tag stays an annotated tag of that commit, and a tag of a tag
        stays a chain of tags. Signatures, including one appended after the message, are
        dropped in the clean phases too. Returns an error string, or None. Objects come
        from the source through
        alternates, so the sealed mutant (written into the source) is visible without a copy."""
        git, env = _Authority.git_bin(), _Authority.git_env()
        code, _, gerr = _run([git, "init", "-q", repo], timeout=60, env=env)
        if code != 0:
            return f"could not create the {phase} repository: {gerr.strip()}"
        code, common, gerr = _run([git, "-C", top, "rev-parse", "--git-common-dir"],
                                  timeout=30, env=env)
        if code != 0:
            return f"could not locate the source object store for the {phase} repository: {gerr.strip()}"
        common_path = Path(common.strip())
        if not common_path.is_absolute():
            common_path = Path(top) / common_path
        objects = (common_path / "objects").resolve()
        alt = Path(repo) / ".git" / "objects" / "info" / "alternates"
        alt.parent.mkdir(parents=True, exist_ok=True)
        # The checkout path is a filesystem path. ascii fails when it contains
        # a non-ASCII directory (PR #571 review); the bytes git will open are
        # the filesystem encoding.
        alt.write_bytes(os.fsencode(str(objects)) + b"\n")
        code, listing, gerr = _run([git, "-C", top, "for-each-ref", "--format=%(refname)"],
                                   timeout=60, env=env)
        if code != 0:
            return f"could not read the source refs for the {phase} repository: {gerr.strip()}"
        for ref in listing.splitlines():
            code, direct, gerr = _run([git, "-C", top, "rev-parse", "--verify", ref],
                                      timeout=30, env=env)
            if code != 0:
                return f"could not resolve {ref} for the {phase} repository: {gerr.strip()}"
            direct = direct.strip()
            code, peeled, _ = _run([git, "-C", top, "rev-parse", "--verify", f"{ref}^{{commit}}"],
                                   timeout=30, env=env)
            peeled = peeled.strip() if code == 0 else ""
            if direct == commit:
                target = direct  # a lightweight ref already at this phase's commit
            elif peeled == head and direct != head:
                target, tag_err = _retarget_tag(top, repo, direct, commit)
                if tag_err:
                    return f"could not retarget {ref} in the {phase} repository: {tag_err}"
            elif direct == head or peeled == head:
                target = commit
            else:
                target = direct
            code, _, gerr = _run([git, "-C", repo, "update-ref", ref, target], timeout=30, env=env)
            if code != 0:
                return f"could not copy {ref} into the {phase} repository: {gerr.strip()}"
        code, sym, _ = _run([git, "-C", top, "symbolic-ref", "-q", "HEAD"], timeout=30, env=env)
        if code == 0 and sym.strip():
            code, _, gerr = _run([git, "-C", repo, "symbolic-ref", "HEAD", sym.strip()],
                                 timeout=30, env=env)
            if code != 0:
                return f"could not set HEAD in the {phase} repository: {gerr.strip()}"
        # The phase repository names no attributes or ignore file of its own, so git would open
        # its default user ones (~/.config/git/attributes and .../ignore, the worker's to write on a
        # one-uid host): a FIFO there blocked this checkout (PR #724 re-attack). Pinned to
        # /dev/null on this call's own command line; the verifier's pinned environment is unchanged,
        # so the system attributes file stays readable here (see docs/runtime-scripts.md).
        code, _, gerr = _run([git, "-C", repo, "-c", f"core.attributesFile={os.devnull}",
                              "-c", f"core.excludesFile={os.devnull}", "reset", "--hard", "--quiet",
                              str(commit)], timeout=120, env=env)
        if code != 0:
            return f"could not check out the {phase} commit: {gerr.strip()}"
        return None

    def _phase_run(top, head, commit, phase, argv, pinned_exec=None, extra_staged_ops=(), absent_mod_paths=()):
        """Run the bound command once in a FRESH repository at `commit`, under a FRESH empty
        HOME and TMPDIR. Returns (rc, stdout, stderr), or (None, None, err) when no repo was made.

        Every phase is built identically — same holder layout, same environment keys, a clean tree,
        the same branch names — and nothing one phase writes under its HOME, TMPDIR or repository
        survives into the next. A branch ref that pointed at head_sha points at this phase's
        commit, so comparing HEAD to that ref cannot tell the control from a clean run."""
        holder = tempfile.mkdtemp(prefix="orca-nc-")
        repo, home, tmp = (str(Path(holder) / leaf) for leaf in ("repo", "home", "tmp"))
        os.mkdir(home)
        os.mkdir(tmp)
        env = {**_Authority.nc_env(), "HOME": home, "TMPDIR": tmp, "TMP": tmp, "TEMP": tmp}
        try:
            err = _stage_phase_repo(top, head, commit, repo, phase)
            if err:
                return None, None, err
            staged_ops = list(dict.fromkeys([*_Authority._staged_script_operands(argv), *extra_staged_ops]))
            pre_op_digests = {}
            for s_op in staged_ops:
                s_digest, s_err = _Authority._verify_staged_rel_file(repo, s_op)
                if s_err:
                    return None, None, s_err
                pre_op_digests[s_op] = s_digest
            for abs_rel in absent_mod_paths:
                if os.path.lexists(os.path.join(repo, abs_rel)):
                    return None, None, (f"proof module shadow {abs_rel!r} appeared before {phase}; "
                                        "fail-closed (#750 C19)")
            exec_argv = list(argv)
            if pinned_exec is not None:
                _, exec_err = _Authority.nc_exec_identity(
                    argv, top, env.get("PATH", ""), pinned_exec, f"before {phase}")
                if exec_err:
                    return None, None, exec_err
                for rec in pinned_exec:
                    slot_idx, pinned_abs = rec[0], rec[2]
                    if 0 <= slot_idx < len(exec_argv) and not os.path.isabs(exec_argv[slot_idx]):
                        exec_argv[slot_idx] = pinned_abs
            rc, out, errout = _run_at(repo, exec_argv, timeout=NC_TIMEOUT_S, env=env)
            for s_op, want_digest in pre_op_digests.items():
                post_digest, post_s_err = _Authority._verify_staged_rel_file(repo, s_op)
                if post_s_err:
                    return None, None, post_s_err
                if post_digest != want_digest:
                    return None, None, (f"proof input {s_op!r} changed during {phase}; "
                                        "fail-closed (#750 C19)")
            for abs_rel in absent_mod_paths:
                if os.path.lexists(os.path.join(repo, abs_rel)):
                    return None, None, (f"proof module shadow {abs_rel!r} appeared during {phase}; "
                                        "fail-closed (#750 C19)")
            if pinned_exec is not None:
                _, post_err = _Authority.nc_exec_identity(
                    argv, top, env.get("PATH", ""), pinned_exec, f"during {phase}")
                if post_err:
                    return None, None, post_err
            return rc, out, errout
        finally:
            shutil.rmtree(holder, ignore_errors=True)

    # The three helpers above are nested, not module names: the RV-D2 width pin
    # (tests/test_reshape_width_verify.py) holds verify.py's top-level surface fixed.
    nc = m.get("negative_control") or {}
    tool = nc.get("tool")
    if tool not in EXECUTABLE_NC_TOOLS or _Authority.unreplayable_tool(m, nc, tool):
        return False, [f"--execute-nc: no replay is implemented for negative_control.tool {tool!r} "
                       f"— only {list(EXECUTABLE_NC_TOOLS)} can be re-executed here; fail-closed "
                       "(#255)"]
    head = m.get("head_sha")
    if not (head and HEX40_RE.match(str(head))):
        return False, ["--execute-nc: head_sha must be a pinned 40-hex commit to check out a "
                       "control worktree"]
    top = _toplevel()
    if top is None:
        return False, ["--execute-nc: not inside a git repo — cannot create a control worktree"]
    if _git(["cat-file", "-e", f"{head}^{{commit}}"])[0] != 0:
        return False, [f"--execute-nc: head_sha '{head}' is not a real commit here"]
    argv, err = _nc_command(nc, nc_command)
    if err:
        return False, [f"--execute-nc: {err}"]
    pinned_exec, exec_err = _Authority.nc_exec_identity(argv, top)
    if exec_err:
        return False, [f"--execute-nc: {exec_err}"]
    extra_staged_ops, absent_mod_paths = [], []
    py_mod = _Authority._python_module_target(argv)
    if py_mod is not None:
        mod_parts = py_mod.split(".")
        mod_rel = "/".join(mod_parts)
        entry_cands = [f"{mod_rel}.py", f"{mod_rel}/__main__.py"]
        pkg_cands = [f"{'/'.join(mod_parts[:k])}/__init__.py" for k in range(1, len(mod_parts) + 1)]
        all_cands = list(dict.fromkeys([*entry_cands, *pkg_cands]))
        ls_rc, ls_out, _ = _run(
            [_Authority.git_bin(), "-C", top, "--literal-pathspecs", "ls-tree", "-r", "-z", head, "--", *all_cands],
            timeout=10, env=_Authority.git_env())
        tracked_mods = {}
        if ls_rc == 0 and ls_out:
            for rec_line in ls_out.split("\0"):
                if not rec_line or "\t" not in rec_line:
                    continue
                meta, rel_p = rec_line.split("\t", 1)
                parts_m = meta.split()
                if parts_m and parts_m[0] in ("100644", "100755"):
                    tracked_mods[rel_p] = parts_m[0]
        if not any(ec in tracked_mods for ec in entry_cands):
            return False, [f"--execute-nc: unsupported proof command: module '-m {py_mod}' is not a tracked "
                           "regular file in head_sha; fail-closed (#750 C19)"]
        if f"{mod_rel}/__main__.py" not in tracked_mods and f"{mod_rel}/__init__.py" in tracked_mods:
            return False, [f"--execute-nc: unsupported proof command: package '{mod_rel}/__init__.py' "
                           f"shadows '{mod_rel}.py' without __main__.py; fail-closed (#750 C19)"]
        req_pkgs = [
            f"{'/'.join(mod_parts[:k])}/__init__.py"
            for k in range(
                1,
                len(mod_parts) + (1 if f"{mod_rel}/__main__.py" in tracked_mods else 0),
            )
        ]
        if any(rp not in tracked_mods for rp in req_pkgs):
            return False, [f"--execute-nc: unsupported proof command: package hierarchy for '-m {py_mod}' "
                           "is missing tracked __init__.py in head_sha; fail-closed (#750 C19)"]
        extra_staged_ops = [c for c in all_cands if c in tracked_mods]
        sib_cands = [f"{'/'.join(mod_parts[:k])}.py" for k in range(1, len(mod_parts))]
        absent_mod_paths = [c for c in [*all_cands, *sib_cands] if c not in tracked_mods]
    for st_op in _Authority._staged_script_operands(argv):
        norm_st_op = Path(os.path.normpath(st_op)).as_posix()
        if os.path.isabs(st_op) or norm_st_op in ("", ".") or ".." in Path(norm_st_op).parts:
            return False, [f"--execute-nc: proof input {st_op!r} is not a tracked "
                           "regular file in head_sha; fail-closed (#750 C19)"]
        ls_rc, ls_out, _ = _run(
            [_Authority.git_bin(), "-C", top, "--literal-pathspecs", "ls-tree", head, "--", norm_st_op],
            timeout=10, env=_Authority.git_env())
        if ls_rc != 0 or not ls_out.strip() or ls_out.strip().split(None, 1)[0] not in ("100644", "100755"):
            return False, [f"--execute-nc: proof input {st_op!r} is not a tracked "
                           "regular file in head_sha; fail-closed (#750 C19)"]
    try:
        mutant, err = _prepare_control(top, head, m, nc, tool, nc_command)
    except _Authority.DriverQueryFailed as fail:
        # Every driver-reading leg (populate, checkout, revert, apply, seal) runs inside
        # _prepare_control; an unreadable driver list stops the control there (PR #649 review).
        return False, [f"--execute-nc: cannot read the control worktree's driver config, so its "
                       f"filter and merge commands cannot be neutralised ({fail}); fail-closed"]
    if err:
        return False, [f"--execute-nc: {err}"]
    msgs = []
    for phase, commit in (("clean", head), ("control", mutant), ("clean", head)):
        rc, out, errout = _phase_run(
            top, head, commit, phase, argv, pinned_exec, extra_staged_ops, absent_mod_paths
        )
        if rc is None:
            return False, [f"--execute-nc: {errout}"]
        tail = (errout.strip() or out.strip())[-300:]
        if phase == "clean":
            if rc != 0:
                when = "after" if msgs else "before"
                return False, [f"--execute-nc: the bound command exits {rc} at CLEAN head_sha "
                               f"({when} the control run), so a RED under the control is not "
                               f"evidence of anything: {tail}"]
            if msgs:
                msgs.append("NOTE: the same command exits 0 at clean head_sha, before AND after "
                            "the control run — the RED above is the control's doing, not a "
                            "broken suite or a first-run side effect")
            continue
        if rc == 124:
            return False, [f"--execute-nc: the bound command did not complete under the control "
                           f"({NC_TIMEOUT_S}s timeout / exec error): {tail}"]
        if rc == 0:
            return False, ["--execute-nc: TAUTOLOGICAL — the proof does NOT go RED. The control "
                           f"was applied at head_sha and `{shlex.join(argv)}` still exited 0, so "
                           "the command does not bind to the change it claims to prove (#255)"]
        sig_ok, sig_err = _verify_sig._failure_signature(out, errout)
        if not sig_ok:
            return False, [f"--execute-nc: {sig_err} Output was: {tail}"]
        msgs.append(f"NOTE: negative control EXECUTED — with the {tool} control applied at "
                    f"head_sha the bound command exited {rc} on an assertion failure (RED, as "
                    "required)")
    return True, msgs


def check_negative_control(m, is_mutation, execute=False, nc_command=None):
    """4. Structured NC AND the artifact must corroborate the pinned mutant being killed. Reading the
    artifact resolves the mutant + verdict; it is corroboration, not proof (a fabricated artifact can
    still be read). Under `execute` the control is additionally RE-EXECUTED (execute_negative_control)
    — that is the only leg that turns the manifest's claim into a fact.

    Returns (errs, executed_ok). `executed_ok` is what the review-waiver lanes require (#256)."""
    if not is_mutation:
        return [], False
    nc = m.get("negative_control") or {}
    errs = []
    tool = nc.get("tool")
    if tool not in NC_TOOLS:
        errs.append(f"negative_control.tool must be one of {sorted(NC_TOOLS)}, got {tool!r}")
    result_text = nc.get("result") or ""
    if not re.search(r"(?i)\b(killed|red)\b", result_text):
        errs.append("negative_control.result must record the mutant KILLED / the proof going RED")
    elif re.search(r"(?i)(?:\bnot\b|\bnever\b|n't\b)[^.;]{0,20}\b(?:killed|red)\b",
                   result_text):
        # "the mutant was NOT killed" satisfied the bare keyword scan (#382); the narrated
        # field gets the same negation guard the artifact-level _NC_ZERO_KILL_RE applies.
        errs.append("negative_control.result negates the kill ('not killed' is not KILLED)")
    mutant = nc.get("mutant")
    if tool and tool not in ("revert", "hand") and not mutant:
        errs.append("negative_control.mutant (a pinned mutant id) is required for a mutation tool")
    artifact = nc.get("artifact")
    if not artifact:
        errs.append("negative_control.artifact (an evidence path) is required")
        return errs, False
    content, err = read_artifact(m, artifact)
    if err:
        errs.append(f"negative_control.artifact unreadable ({artifact}): {err}")
        return errs, False
    content = content.decode("utf-8", "replace")
    if not re.search(r"(?i)\b(killed|red|fail)\b", content):
        errs.append("negative_control.artifact does not evidence a killed/RED outcome")
    if _NC_ZERO_KILL_RE.search(content):
        errs.append("negative_control.artifact indicates no mutant was killed (0 killed / 0% killed)")
    # the pinned mutant must not be reported as surviving — scoped to the mutant id and tolerant of
    # delimiters (`m7: Survived: 1`, `m7 - survived - 0`), but a zero count is a KILL. The lookahead
    # excludes `<>` so a comparison like `survived > 0` is NOT read as a zero count (it is a survivor).
    surv = r"survived\b(?![\s:=-]*0\b)"
    if re.search(rf"(?i)\bmutant\s+{surv}", content) or (
            mutant and re.search(rf"(?i)\b{re.escape(mutant)}\b[\s:=<>-]*(?:has\s+|was\s+)?{surv}", content)):
        errs.append("negative_control.artifact reports the pinned mutant SURVIVED / was not killed")
    if mutant and mutant not in content:
        errs.append("negative_control.artifact does not reference the pinned mutant")
    if tool == "hand":
        # `hand` is exempt from a pinned mutant id, so the diff it applied is the ONLY thing binding
        # the RED to a mutation — the artifact must quote it (evidence-manifest §1).
        has_diff = re.search(r"(?m)^(diff --git|@@ )", content) or (
            re.search(r"(?m)^-[^-]", content) and re.search(r"(?m)^\+[^+]", content))
        if not has_diff:
            errs.append("negative_control.artifact for tool 'hand' must quote the hand-written diff")
    # Binding the control's paths to the change is a STATIC check — the declared paths against
    # base_sha..head_sha — so it belongs here, on every mutation unit, not only on the executed
    # leg. It lived solely in _apply_control, which meant a NARRATED manifest could nominate a
    # decoy path, or revert the test that encodes the criterion, and nothing looked (#306).
    #
    # Executed, those two are caught anyway: reverting a file the change never touched is a no-op
    # and #255 refuses it. That is why the gap survived #280 — the executed lane covered for the
    # narrated one, and no trap sampled the narrated lane until now.
    if tool == "revert":
        declared, perr = _nc_paths(nc)
        if perr:
            errs.append(perr)
        elif declared:
            bind_err = _bind_paths_to_change(declared, m, "negative_control.paths", nc_command)
            if bind_err:
                errs.append(bind_err)
        elif all(HEX40_RE.match(str(m.get(k) or "")) for k in ("base_sha", "head_sha")):
            _prod, oracle, bind_err = _changed_paths(m["base_sha"], m["head_sha"], nc_command)
            if bind_err:
                errs.append(bind_err)
            elif oracle:
                errs.append(f"range revert changes test paths or runner oracle inputs {sorted(oracle)}; "
                            "name only production negative_control.paths")
    elif tool in EXECUTABLE_NC_TOOLS:
        # The same bind, one tool over. `hand` (and any mutation tool that quotes its mutant diff)
        # declares its target in the quoted diff rather than in paths[], and checking that the
        # artifact merely CONTAINS diff-shaped text left the decoy open: a narrated manifest could
        # quote a diff against a file the change never touched, or an unrelated hunk, and offer its
        # RED as evidence (PR #308 review, P1). Caught only under --execute-nc before, which is the
        # identical asymmetry #306 closed for `revert` — the executed lane covering for the narrated one.
        quoted = _extract_diff(content)
        # Only when the manifest actually pins its SHAs. A mutation manifest that does not is
        # already refused by check_real_commits, which owns that fact; repeating the refusal here
        # would couple a structural check to git state and say the same thing twice.
        pinned = all(HEX40_RE.match(str(m.get(k) or "")) for k in ("base_sha", "head_sha"))
        if quoted and pinned:
            targets, parse_err = set(), None
            try:
                targets.update(_iter_diff_target_paths(quoted))
            except ValueError as exc:
                parse_err = str(exc)
            # Even a truncated patch can name a decoy. Keep that specific diagnostic AND
            # the syntax rejection; a partial inventory can never authorize execution.
            bind_err = _bind_paths_to_change(targets, m, "the hand mutant's diff", nc_command)
            if bind_err:
                errs.append(bind_err)
            hunk_err = parse_err or _bind_hunks_to_change(quoted, m)
            if hunk_err:
                errs.append(hunk_err)
    executed_ok = False
    if execute and not errs:
        executed_ok, msgs = execute_negative_control(m, nc_command)
        errs.extend(msgs)
    return errs, executed_ok


def check_commands(m, is_mutation, nc_command=None):
    """5. The CONTENT-BOUND evidence ledger (audit §3 item 3; gstack `bin/gstack-evidence`).

    "Tests pass at that exact SHA in a clean env" was doctrine — a sentence in evidence-manifest §2
    addressed to the coordinator, with no field any verifier read. `evidence-run.py` records
    `{cmd, cmd_sha256, exit, duration_s, commit, wtree, artifact}` for every command it wraps, and
    this check requires at least ONE record with `exit == 0` whose `wtree` equals
    `git rev-parse <head_sha>^{tree}` — the content actually committed at the head. A record made on
    other content (an earlier tree, a dirty tree with extra files) is STALE and does not count.

    When the coordinator names the proof command out of band (`--nc-command`), one of those fresh
    records must be FOR THAT command — otherwise `evidence-run.py -- true` satisfies the gate and
    "tests really ran on this content" is asserted of a run that ran no tests (#352).

    FAIL-CLOSED, unlike upstream's advisory `check`: no record means nothing proved the suite ran on
    this content. The NOTE says what the pass does NOT mean — the coordinator's clean-env re-run is
    still the stronger authority, because this record was written by the worker's own runner."""
    if not is_mutation:
        return []
    head = m.get("head_sha")
    if not head:
        return []  # check_shas_present already fails this manifest
    code, want = _git(["rev-parse", f"{head}^{{tree}}"])
    if code != 0 or not want:
        return ["commands ledger: cannot resolve the tree of head_sha (not a real commit here, or "
                "not inside a git repo) — the recorded run cannot be bound to content; fail-closed"]
    records = [c for c in (m.get("commands") or []) if isinstance(c, dict)]
    if not records:
        return ["commands ledger: no recorded command (mutation unit). Wrap the criterion-bound "
                "run in `runtime/scripts/evidence-run.py --label <L> --manifest <m.json> -- <cmd>` "
                "so the manifest carries an exit code bound to a content fingerprint; fail-closed"]
    # A record whose cmd_sha256 does not hash its own cmd describes nothing, so it binds nothing:
    # a decorative digest would let the line be edited after the run. Checked here rather than at
    # the point of use, because since #279 the replay no longer draws its command from this ledger
    # and the integrity of the ledger is still worth asserting.
    for rec in records:
        line = rec.get("cmd")
        digest = rec.get("cmd_sha256")
        if not (isinstance(line, str) and isinstance(digest, str)):
            continue
        actual = hashlib.sha256(line.encode("utf-8")).hexdigest()
        if digest != actual:
            return [f"commands ledger: record for {line!r} carries cmd_sha256 {digest} but the "
                    f"command line hashes to {actual} — the record does not describe its own "
                    "command, so it binds nothing; fail-closed"]
    fresh, _ = _fresh_command_records(m)
    if not fresh:
        # PR #649 review (PRRT_kwDOTWxN9c6vwb7P): an exit-0 run evidence-run.py could not
        # fingerprint because a repository-declared filter selects a changed path is UNVERIFIABLE,
        # not stale — its content cannot be compared without running the repo's command, which
        # nothing here does. Say so. The reason is worker-written: shown truncated and repr()'d,
        # and it only ever words a refusal, never lifts one.
        why = next((c["wtree_unverifiable"] for c in records if c.get("exit") == 0
                    and c.get("wtree") is None and isinstance(c.get("wtree_unverifiable"), str)),
                   None)
        if why is not None:
            return [f"commands ledger: the exit-0 run carries no fingerprint for head_sha's tree "
                    f"{want} because its working tree was UNVERIFIABLE, not stale: "
                    f"{why[:300]!r} — the coordinator's clean-env re-run at head_sha is the "
                    "authority for this unit; fail-closed (#629)"]
        seen = sorted({str(c.get("wtree")) for c in records if c.get("exit") == 0})
        return [f"commands ledger: no recorded command with exit 0 whose wtree is head_sha's tree "
                f"{want} (exit-0 records carry {seen or 'no wtree at all'}) — the recorded run was "
                "made on other content, so it is STALE evidence for this head; fail-closed"]
    if nc_command is not None:
        # The coordinator named the proof command out of band (#279); the ledger must show THAT
        # command green on this content, not merely some exit-0 record — `evidence-run.py -- true`
        # is content-bound and still proves nothing (#352). Same shlex normalization as
        # _nc_command's agreement rule, so quoting differences alone cannot split the comparison.
        try:
            want_cmd = shlex.join(shlex.split(nc_command))
        except ValueError:
            want_cmd = None
        if not want_cmd:
            # An empty or unparseable --nc-command must not silently downgrade the gate to
            # pre-#352 behavior (PR #387 security review): the named-command check cannot run,
            # so the answer is RED, not a quiet skip.
            return [f"commands ledger: --nc-command {nc_command!r} is empty or unparseable — "
                    "the coordinator named no usable proof command; fail-closed (#352)"]
        def _matches(rec):
            line = rec.get("cmd")
            if not isinstance(line, str):
                return False
            try:
                return shlex.join(shlex.split(line)) == want_cmd
            except ValueError:
                return False
        if not any(_matches(rec) for rec in fresh):
            ran = sorted({str(rec.get("cmd")) for rec in fresh})
            return [f"commands ledger: fresh exit-0 record(s) exist, but none is the "
                    f"coordinator-named proof command {want_cmd!r} (fresh records ran: {ran}) "
                    "— the ledger proves SOMETHING ran green on this content, not the proof the "
                    "coordinator named; fail-closed (#352)"]
    return [f"NOTE: commands ledger FRESH — {len(fresh)} exit-0 record(s) bound to head_sha's tree "
            f"{want[:12]}. This is the worker's own runner, so the coordinator's clean-env re-run at "
            "head_sha still stands as the stronger authority (evidence-manifest.md §2)"]


def _gitleaks_scan(path):
    """Scan one file with gitleaks when it is installed. Returns True (hit) / False (clean) / None
    (gitleaks unusable — the caller falls back to the built-in patterns)."""
    if _Authority.gitleaks_custody is None:  # a library caller: pin on first use, once (h409 R2)
        _Authority.pin_gitleaks()
    if _Authority.gitleaks is None:
        return None
    if _Authority.gitleaks_custody != "system" and _Authority.lane:
        return None  # W3-10: never run a worker-replaceable scanner on a sound lane; the floor runs
    # cwd is the evidence copy's directory, never the unit checkout: gitleaks
    # otherwise inherits the process cwd (the worker/test repo) and can write
    # under .git/objects while tests tear that tree down (#340).
    # Uses _run (not _run_at): _run_at is the negative-control executor, and
    # admission tests assert it is not called before a control is authorized.
    code, _, _ = _run([_Authority.gitleaks, "detect", "--no-git", "--no-banner", "--redact",
                       "--source", str(path)], timeout=120, cwd=str(Path(path).parent),
                      env=_Authority.git_env())
    if code == 0:
        return False
    if code == 1:
        return True
    return None


def check_redaction(m, manifest_path):
    """6. Redaction (audit §3 item 14). A manifest is SHA-pinned and permanent, and so is anything
    quoted into it or into an artifact it names. Scan the manifest JSON and every named artifact
    (the negative control's, the reviewer record, the `artifacts[]` inventory, and each
    `commands[].artifact`) for credential shapes. REDACTION_PATTERNS always supplies the floor;
    Gitleaks adds detections when installed. A hit FAILS the unit — rotate the credential, scrub the
    evidence, re-emit.

    `commands[].artifact` is the captured stdout/stderr of a recorded run, so it is the likeliest
    place a token lands and the last one added here: scanning every other named path while
    skipping that one let a clean-looking unit pin a live credential (#309)."""
    errs = []
    targets = [("manifest", json.dumps(m).encode("utf-8"))]
    if isinstance(m, _EvidenceManifest):
        targets.append(("manifest bytes", m.raw))
    elif manifest_path:
        try:
            targets.append(("manifest bytes", Path(manifest_path).read_bytes()))
        except OSError as exc:
            errs.append(f"redaction: manifest unreadable: {exc}")
    named = []
    for path in ((m.get("negative_control") or {}).get("artifact"),
                 (m.get("review") or {}).get("artifact")):
        if isinstance(path, str) and path:
            named.append(path)
    for entry in (m.get("artifacts") or []):
        path = entry.get("path") if isinstance(entry, dict) else entry
        if isinstance(path, str) and path:
            named.append(path)
    for entry in (m.get("commands") or []):
        path = entry.get("artifact") if isinstance(entry, dict) else None
        if isinstance(path, str) and path:
            named.append(path)
    for path in dict.fromkeys(named):
        raw, err = read_artifact(m, path)
        if err:
            errs.append(f"redaction: artifact {path} unreadable: {err}")
        else:
            targets.append((f"artifact {path}", raw))
    # Scan a private copy of the pinned bytes, never the mutable checkout overlay.
    with tempfile.TemporaryDirectory(prefix="orca-redaction-") as folder:
        scan_path = Path(folder) / "evidence.txt"
        for label, raw in targets:
            text = raw.decode("utf-8", "replace")
            kinds = sorted({name for name, rx in REDACTION_PATTERNS if rx.search(text)})
            scan_path.write_bytes(raw)
            if _gitleaks_scan(scan_path) is True and not kinds:
                kinds = ["gitleaks-rule"]
            if kinds:
                errs.append(f"redaction: credential shape(s) {kinds} found in {label} — evidence is "
                            "SHA-pinned and permanent; rotate the credential and re-emit the unit")
    return errs


def check_ancestry(m, base):
    """7. head_sha is an ancestor of origin/<base> (post-merge).

    A coordinator that NAMES a base asked for this fact. On the advisory native lane a missing
    origin/<base> is still a NOTE (pre-merge, offline, a clone that never fetched). On a lane
    claiming soundness (_Authority.lane: --provenance ci|mcp|sdk|dispatch, or a signed dispatch
    record + a pinned pubkey) it is FATAL, as every other authority leg is there: the ref lives in the
    clone the worker controls, and deleting it must not turn a requested ancestry proof into a
    skipped one (review P2). The ref is resolved by its exact name, once (W3-07)."""
    if not base:
        return ["NOTE: --base not given — ancestry check skipped (pre-merge/offline)"]
    # The FULL ref name: gitrevisions resolves a short `origin/<base>` through refs/tags first, so
    # a tag (or local branch) named origin/<base> that a worker can push shadowed the
    # remote-tracking branch and put any commit "on base" (2026-10-26 review) — and the full name
    # is looked up EXACTLY, never expanded (W3-07).
    shown, ref = f"origin/{base}", f"refs/remotes/origin/{base}"
    tip, _target, why = _Authority.anchor_commit(ref)  # once; every read below names `tip`
    if tip is None:
        why = f"{ref} {why}"
        if _Authority.lane:
            return [f"ancestry: {shown} not found — a lane claiming soundness ({_Authority.lane}) "
                    "named --base and cannot skip the ancestry proof it asked for; fail-closed "
                    f"({why})"]
        return [f"NOTE: {shown} not found — ancestry check skipped ({why})"]
    if _git(["merge-base", "--is-ancestor", m.get("head_sha", ""), tip])[0] != 0:
        return [f"head_sha is not an ancestor of {shown} (not merged / wrong base)"]
    return []


def check_symbol_on_base(symbol, base):
    """8. Best-effort: a unit symbol is greppable on origin/<base> (change is real on base),
    read at the commit _Authority.anchor_commit resolves by exact name (W3-07)."""
    if not symbol or not base:
        return []
    ref = f"refs/remotes/origin/{base}"
    tip, _target, why = _Authority.anchor_commit(ref)  # once (W3-07); the grep names `tip`
    if tip is None:
        return [f"symbol '{symbol}' not found on origin/{base}: the base does not resolve by its "
                f"exact name ({ref} {why})"]
    # timeout=20 is the LEGACY allowance, restored explicitly (#442 S2-R3). This leg used to
    # call _run, whose default is 20s; routing it through _git for the SHA root (#442) silently
    # halved the budget to _git's 10s default, and a grep that took 11s turned a symbol that IS
    # on base into a fatal "not found". The root selection was the change; the clock was not.
    code, out = _git(["grep", "-l", "-e", symbol, tip], timeout=20)
    if code != 0 or not out.strip():
        return [f"symbol '{symbol}' not found on origin/{base} (change may not be on base)"]
    return []


def check_base_binding(m, base, execute_nc):
    """7b. base_sha is a commit the integration branch holds (2026-10-26 review, P0).

    The executed control restores `negative_control.paths` from base_sha and the changed-production
    denominator is base_sha..head_sha, yet nothing bound base_sha to coordinator state: a worker
    that inserts a poison commit (production code that fails under any call) and declares it as
    base_sha turns any test RED under the revert and GREEN at a head that is wrong for the
    criterion — a complete bypass on the lanes where the control is the only oracle. Named a
    base, the gate now requires base_sha to be an ancestor of refs/remotes/origin/<base>: a commit
    the worker could not have put there. Without --base the control's pre-fix content is unbound:
    a NOTE on the advisory native lane, fatal where a lane claims soundness and executes the
    control. A signed dispatch record may also pin base_sha outright (check_dispatch_provenance).
    The ref is resolved by its exact name, once (_Authority.anchor_commit, W3-07): with it absent, a local
    refs/heads/refs/remotes/origin/<base> holding the poison used to answer for it."""
    base_sha = str(m.get("base_sha") or "")
    if not HEX40_RE.match(base_sha):
        return []  # check_shas_present / check_real_commits name that defect
    if not base:
        if execute_nc and _Authority.lane:
            return [f"base binding: a lane claiming soundness ({_Authority.lane}) executes the "
                    "control without --base, so base_sha — the content the control restores — is "
                    "bound to no branch the coordinator owns; name --base (fail-closed)"]
        if execute_nc:
            return ["NOTE: --base not given — base_sha, the content the executed control restores, "
                    "is bound to no branch (worker-chosen on this lane)"]
        return []
    tip, _target, _why = _Authority.anchor_commit(f"refs/remotes/origin/{base}")  # once (W3-07)
    if tip is None:
        return []  # check_ancestry reports the unresolved ref (a NOTE or fatal by lane)
    if _git(["merge-base", "--is-ancestor", base_sha, tip])[0] != 0:
        return [f"base_sha {base_sha[:12]} is not an ancestor of origin/{base} — the control would restore "
                "content the integration branch never held, so the worker chose its own base "
                "(2026-10-26 review)"]
    return []


def check_intent(m, is_mutation):
    """9. Mutation units carry a non-empty intent packet (goal · ruled_out · why) — presence only;
    wisdom is a human/taste check (evidence-manifest.md §1)."""
    if not is_mutation:
        return []
    intent = m.get("intent")
    if not isinstance(intent, dict):
        intent = {}
    missing = [k for k in ("goal", "ruled_out", "why")
               if not (isinstance(intent.get(k), str) and intent.get(k).strip())]
    return [f"intent packet incomplete — non-empty {missing} required (mutation unit)"] if missing else []


def check_lighting(m, is_mutation, dispatch_lighting=None, dispatch_lane=None):
    """10. Lighting is a legal value when present; omission defaults to lit — "Recording nothing
    means lit" (gate-classification.md). dark-eligibility's stop-list is a human gate; verify.py
    machine-checks that the value is legal and, when the dispatch supplied a lighting, that the
    worker's manifest did not swap it (the dispatch value is authoritative for the review waiver
    in check_review). Omission being lit means a dark-eligible dispatch + omitted manifest
    lighting is a swap. Lane rides this same leg: with a dispatch-supplied `--lane` (likewise
    authoritative) a manifest `lane` may record it but not swap it, a Lane-0 unit may not be
    verified as a landed mutation, and dark-eligibility requires Lane A — the halves of
    dark-eligibility that used to rest on narration because verify.py never saw lane data."""
    if not is_mutation:
        return []
    lighting = m.get("lighting", "lit")  # omission means lit (gate-classification.md); an
    # explicit null is a present value, not omission, and fails the legality check below
    if not (isinstance(lighting, str) and lighting in LIGHTING_VALUES):
        return [f"lighting must be one of {sorted(LIGHTING_VALUES)}, got {lighting!r}"]
    if dispatch_lighting is not None and lighting != dispatch_lighting:
        return [f"lighting swap: manifest says {lighting!r} but dispatch classed the unit "
                f"{dispatch_lighting!r} (the dispatch value is authoritative)"]
    lane = m.get("lane")
    if lane is not None and lane not in ("A", "B", "0"):
        return [f"lane must be one of {['A', 'B', '0']}, got {lane!r}"]
    if dispatch_lane is None:
        return []
    if lane is not None and lane != dispatch_lane:
        return [f"lane swap: manifest says {lane!r} but dispatch classed the unit "
                f"{dispatch_lane!r} (the dispatch value is authoritative)"]
    if dispatch_lane == "0":
        return ["Lane 0 (refuse-and-surface) unit is being verified as a landed mutation — "
                "Lane 0 work is recorded and surfaced, never built (gate-classification.md)"]
    effective = dispatch_lighting if dispatch_lighting is not None else lighting
    if effective == "dark-eligible" and dispatch_lane != "A":
        return [f"dark-eligible unit on Lane {dispatch_lane}: dark-eligibility requires "
                "Lane A (gate-classification.md)"]
    return []


def check_reviewer_mode(m, is_mutation):
    """11. reviewer_mode is recorded and legal — how independent the review was. The strongest
    independence signal is the APPROVED GitHub review (check_review); this records the qualifier."""
    if not is_mutation:
        return []
    mode = m.get("reviewer_mode")
    if not (isinstance(mode, str) and mode in REVIEWER_MODES):
        return [f"reviewer_mode must be one of {sorted(REVIEWER_MODES)}, got {mode!r}"]
    return []


def check_provenance(m):
    """12. EU AI Act Art-12/50: a manifest that CLAIMS a regulated standard must carry the provenance
    fields that make it an audit record. Presence-only (not deep validation), but an incomplete packet
    claiming a standard is not a valid audit record — fail it rather than accept incomplete evidence."""
    prov = m.get("provenance")
    if not isinstance(prov, dict):
        return []
    standard = prov.get("standard")
    if not (isinstance(standard, str) and standard.strip() and standard.strip().lower() != "none"):
        return []
    missing = [k for k in ("spec_version", "model", "reviewer", "retention")
               if not (isinstance(prov.get(k), str) and prov.get(k).strip())]
    return [f"provenance claims standard {standard!r} but is missing audit fields {missing} "
            "(EU AI Act Art-12/50 record incomplete)"] if missing else []


def check_retention_receipt(m, pubkey_ref=None):
    """12b. #608: the OFFLINE binding of `provenance.retention` — the path of a v1 transparency-log
    receipt (inventory.py RECEIPT_SCHEMA) — to the signed run-close inventory it names and to THIS
    manifest. check_provenance above stays presence-only; this check is what makes it binding.

    The binding is CLAIMED by the manifest (`provenance.retention_receipt`, the schema id) or by the
    coordinator handing over trust material (--retention-pubkey: a path or path@ref, normally the
    coordinator's .orca/dispatch-pubkey at refs/remotes/origin/main in its OWN clone). Neither: [] — legacy
    provenance keeps its documented presence-only check, and a run that never uploaded owes no
    receipt. A manifest claim with no key supplied fails closed: a key inside a receipt never
    establishes trust, so without the supplied one there is nothing to verify it against.

    Claimed and keyed, every link must hold or the unit is refused: the receipt is read (a
    repo-relative path, bounded like all evidence, #267) → its v1 shape → signer identity and
    signature under the SUPPLIED key → its unit and source revision equal this manifest's `unit`
    and `head_sha` (another run's receipt) → the document it names carries an inventory-signature
    that verifies under the same key over exactly its entries → the receipt's digest is that
    signed digest (another inventory's receipt) → that inventory pins this manifest's exact bytes.
    Neither file is read through the artifacts[] pin: the inventory pins the manifest, so the
    manifest cannot pin the receipt that binds the inventory — both are authenticated by signature.

    Verified: exactly those links, offline; nothing here makes a network call. NOT verified, and
    the NOTE says so: that the log entry exists or is included in any log (a live lookup the
    maintainer runs out of band), any retention period, that the listed files still hash to the
    inventory (inventory.py check / run_report.py), or any legal determination."""
    prov = m.get("provenance") if isinstance(m.get("provenance"), dict) else {}
    claim = prov.get("retention_receipt")
    if claim is None and not pubkey_ref:
        return []
    try:
        spec = importlib.util.spec_from_file_location(
            "inventory", Path(__file__).resolve().parent / "inventory.py")
        inv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inv)
    except Exception as exc:
        return [f"retention receipt binding claimed, but inventory.py — which owns the receipt and "
                f"inventory forms — is unavailable ({exc}); fail-closed (#608)"]
    if claim is not None and claim != inv.RECEIPT_SCHEMA:
        return [f"provenance.retention_receipt claims {claim!r}; this verifier binds "
                f"{inv.RECEIPT_SCHEMA!r} only — fail-closed (#608)"]
    if not pubkey_ref:
        return [f"provenance claims the {claim} retention binding, but no trust material was supplied "
                "(--retention-pubkey) — a key inside a receipt never establishes trust, so there is "
                "nothing to verify it against; fail-closed (#608)"]
    key_where, key_read, _pinned, refused = _Authority.key_source(pubkey_ref, "--retention-pubkey")
    if refused:
        return [refused]
    pub_text, err = read_source(key_read)  # the commit key_source resolved, once
    try:
        pub = b"" if err else bytes.fromhex(pub_text.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        pub, err = b"", str(exc)
    if len(pub) != 32:
        return [f"retention trust key {pubkey_ref} is unreadable or not a 32-byte Ed25519 public "
                f"key ({err or 'wrong length'}) — fail-closed (#608)"]

    def read(what, path):
        """Bytes of a repo-relative file, bounded by _resolve (#267), or the reason why not."""
        if not (isinstance(path, str) and path.strip()):
            return None, f"no {what} path is named"
        if "@" in path:
            return None, f"{what} {path!r} must be a repo-relative path, not a path@ref (#267)"
        full, why = _resolve(path)
        if why:
            return None, f"{what} {path!r} refused: {why}"
        if not full.exists():
            return None, f"{what} {path!r} is missing — no file at that path"
        try:
            return full.read_bytes(), None
        except OSError as exc:
            return None, f"{what} {path!r} is unreadable ({exc})"

    receipt = prov.get("retention")
    raw, err = read("retention receipt", receipt)
    if err:
        return [f"{err}; the retention binding is claimed, so it fails closed (#608)"]
    try:
        envelope = inv.parse_receipt(raw)
    except inv.ReceiptRefused as why:
        return [f"retention receipt {receipt} is unreadable as a v1 receipt ({inv.RECEIPT_SCHEMA}): "
                f"{why} (#608)"]
    try:
        record = inv.verify_receipt(envelope, pub, m.get("unit"), m.get("head_sha"))
    except inv.ReceiptRefused as why:
        return [f"retention receipt {receipt} refused: {why} (#608)"]
    doc, err = read("inventory document", record["inventory"])
    if err:
        return [f"retention receipt {receipt}: {err}; fail-closed (#608)"]
    try:
        digest, entries = inv.bind_receipt(record, doc.decode("utf-8").splitlines(), pub)
    except UnicodeDecodeError as exc:
        return [f"retention receipt {receipt}: {record['inventory']} is not UTF-8 text ({exc}); "
                "fail-closed (#608)"]
    except inv.ReceiptRefused as why:
        return [f"retention receipt {receipt} refused: {why} (#608)"]
    raw_manifest = getattr(m, "raw", None)
    mine = hashlib.sha256(raw_manifest).hexdigest() if raw_manifest is not None else None
    if mine is None or all(pinned != mine for _idx, _path, pinned, _shape in entries):
        return [f"retention receipt {receipt} refused: {record['inventory']} does not pin this "
                f"manifest's exact bytes (sha256 {mine}) — the receipt covers some other record of "
                "this unit (#608)"]
    # W3-04: equal digests let a byte-copy of this manifest at ANOTHER path stand in for it, and
    # the receipt's path story went unchecked. An entry binds only when it resolves — as
    # inventory.py check resolves it: repo root first, then the inventory's own directory — to
    # the very file this manifest was read from; the NOTE names that entry.
    here = getattr(m, "path", None)
    doc_path, top = _resolve(record["inventory"])[0], _evidence_toplevel()

    def same_file(entry):
        found = inv.resolve(entry, doc_path, Path(top) if top else None) if doc_path else None
        try:
            return found is not None and here is not None and found.resolve() == Path(here).resolve()
        except OSError:
            return False

    pinned_at = [path for _idx, path, pinned, _shape in entries if pinned == mine]
    named = [path for path in pinned_at if same_file(path)]
    if pinned_at and not named:
        return [f"retention receipt {receipt} refused: {record['inventory']} pins this manifest's "
                f"bytes only as {pinned_at}, not under this manifest's own path {here!r} — a "
                "byte-copy stands in for the record the receipt claims to cover (W3-04, #608)"]
    return [f"NOTE: retention receipt {receipt} verified OFFLINE against the supplied key — "
            f"{key_where} (W3-03) — (#608): "
            f"signed by {record['signer']} over the {inv.RECEIPT_SCHEMA} payload, binding unit "
            f"{record['unit']!r} at source revision {record['source_revision'][:12]} to inventory "
            f"digest {digest[:12]}… of {record['inventory']}, whose entries carry the same key's "
            f"signature and pin this manifest's bytes as its entry {named[0] if named else None} "
            "(W3-04). NOT verified: that log entry "
            f"{record['entry_uuid'][:16]}… (index {record['log_index']}) exists or is included in "
            "any transparency log (a live lookup run out of band), any retention period or storage, "
            "that the listed files still hash to the inventory (inventory.py check / run_report.py), "
            "or any legal or regulatory determination"]


# The dispatch fields the gate ENFORCES — a mirror of dispatch-sign.py's _RECORD_FIELDS pinned by
# the parity test, never a canonical form: _canonical_dispatch signs through the signer itself, so
# a record carrying the signer's _PROFILE_FIELDS (#590) verifies too (2026-10-23 review, P2-2).
_DISPATCH_FIELDS = ("manifest_id", "contract_digest", "unit_class", "lighting",
                    "nc_paths", "nc_command", "nc_artifact_sha256",
                    "no_gh", "lane", "execute_nc", "allow_static_nc", "base_sha")
# The LANE flags (review P2): --no-gh waives the GitHub review, --lane decides Lane-0 refusal and
# dark-eligibility's Lane-A requirement, and --execute-nc is what turns the control from text into
# a fact. All three reach verify.py through argv / the worker-settable ORCA_* env, so on a
# signed-record lane they are bound like lighting is. Signed only when set — an old record without
# them keeps its exact canonical bytes and still verifies.
# The negative-control inputs among them (#311) are read from the MANIFEST, not from argv, so they
# are compared separately from the CLI-supplied fields above — check_dispatch_provenance names
# them (nc_paths, nc_command, nc_artifact_sha256) at its one comparison.


def _load_ed25519():
    spec = importlib.util.spec_from_file_location("ed25519", Path(__file__).resolve().parent / "ed25519.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _canonical_dispatch(record):
    """dispatch-sign.py's own canonical_record, not a copy of it (2026-10-23 review, P2-2). The
    copy that lived here signed _DISPATCH_FIELDS only, and the signer appends _PROFILE_FIELDS to
    a record carrying a profile (#590), so every genuine `--profile`/`--parent-profile` record
    read as forged. One implementation, loaded from the verifier's own toolchain (dispatch-sign.py
    is in _Transcript.TOOLCHAIN), cannot drift; the parity tests sample profile records too."""
    return _Transcript.signer().canonical_record(record)


class _Transcript:
    """The verifier TRANSCRIPT (#281/#386): this script's verdict as a signable object, so a tier
    can require a verdict the worker could not have typed. One namespace — the RV-D2 width pin
    (tests/test_reshape_width_verify.py) counts top-level names, and four helpers over one record
    are one thing. FIELDS mirrors dispatch-sign.py.TRANSCRIPT_FIELDS."""

    FIELDS = ("unit", "manifest", "manifest_sha256", "args", "fatal", "notes", "exit",
              "toolchain", "timestamp")
    # h409 F-5: the files this verifier IS — itself and every sibling it loads by path. Hashed
    # per file into toolchain.files; run_report.py (TOOLCHAIN_FILES mirrors this) binds each to
    # the file at the graded pin, so a substituted sibling can no longer sign a byte-identical
    # envelope. This binds the verifier's identity, nothing more.
    # #608: check_retention_receipt loads inventory.py (which loads gitexec.py), so both are part
    # of what this verifier IS once a receipt is checked — hashed like every other sibling.
    TOOLCHAIN = ("verify.py", "_verify_sig.py", "diff_scope.py", "ed25519.py", "dispatch-sign.py",
                 "inventory.py", "gitexec.py")
    ARGS = ("contract_source", "contract_digest", "repo", "base", "symbol", "execute_nc",
            "allow_static_nc", "unit_class", "no_gh", "lighting", "lane", "dispatch_record",
            "dispatch_pubkey", "nc_command", "git_dir", "evidence_root", "provenance",
            "retention_pubkey")

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def signer():
        """dispatch-sign.py, loaded once by path the way the other siblings are. It owns the ONE
        canonical form both envelopes are signed over — the dispatch record's and this
        transcript's — and the seed custody rule; verify.py verifies and signs through it rather
        than through copies (2026-10-23 review, P2-2: the dispatch copy lost the profile rule)."""
        spec = importlib.util.spec_from_file_location(
            "dispatch_sign", Path(__file__).resolve().parent / "dispatch-sign.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @classmethod
    def canonical(cls, record):
        """dispatch-sign.py.canonical_transcript itself — one implementation, not a mirror."""
        return cls.signer().canonical_transcript(record)

    @classmethod
    def hash_files(cls):
        """{toolchain file: sha256 hex, or None when it cannot be read} — the verifier's bytes."""
        here = Path(__file__).resolve().parent
        files = {}
        for name in cls.TOOLCHAIN:
            try:
                files[name] = hashlib.sha256((here / name).read_bytes()).hexdigest()
            except OSError:
                files[name] = None  # an absent sibling signs an absence; run_report refuses it
        return files

    @classmethod
    def build(cls, args, exit_code, fatal, notes, raw=None, files=None):
        """The verdict object: what was judged (manifest path AND bytes, the unit it names), with
        what (the full argument tuple — unset flags included, so an omitted authority is visibly
        omitted), what was found (the printed lists, verbatim), the exit code, the toolchain, when.

        `raw` is the manifest bytes verify() actually LOADED and judged (_EvidenceManifest.raw),
        never a second read of args.manifest: by the time the transcript is built the executed
        control has run worker code, which can rewrite the manifest file, and a re-read would
        bind a verdict to bytes nobody judged (review P2). None — a manifest that never loaded —
        records no digest and no unit, and a signed transcript then refuses to sign the absence."""
        manifest_sha, unit = None, None
        if raw is not None:
            manifest_sha = hashlib.sha256(raw).hexdigest()
            try:
                unit = json.loads(raw.decode("utf-8")).get("unit")
            except (ValueError, AttributeError):
                unit = None
        _, git_version, _ = _run([_Authority.git_bin(), "--version"], env=_Authority.git_env())
        # W3-11: `files` is the toolchain as hashed BEFORE verify() ran — the bytes that judged.
        # Hashed here, after the executed control had run worker code, a mid-run rewrite of a
        # sibling was recorded as if it were the verifier.
        files = cls.hash_files() if files is None else files
        return {
            "unit": unit,
            "manifest": args.manifest,
            "manifest_sha256": manifest_sha,
            "args": {k: getattr(args, k) for k in cls.ARGS},
            "fatal": list(fatal),
            "notes": list(notes),
            "exit": exit_code,
            "toolchain": {
                "python": sys.version.split()[0],
                "git": git_version.strip() or None,
                "verify_sha256": files["verify.py"],
                "files": files,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    @staticmethod
    def seed(key_ref):
        """(seed bytes, None) from a gen-key seed file, or (None, reason). Read up front so a bad
        key is a USAGE error (exit 1) before any verdict, not a transcript silently left unsigned.
        h409 F-4: the read is dispatch-sign.py's own _seed, so the custody rule (0600, not in an
        unignored work tree, class named on stderr) is ONE rule shared by all four signers."""
        seed, err = _Transcript.signer()._seed(Path(key_ref))
        return (None, f"--transcript-key: {err}") if err else (seed, None)

    @classmethod
    def write(cls, out_ref, record, seed):
        """Write the verdict object, or — with a seed — the {record, sig_b64} envelope
        dispatch-sign.py emits, over the same canonical bytes. True when the requested artifact
        exists afterwards. Two refusals, both fail-closed like every other evidence path: with a
        seed, a record with any FIELDS value None is never signed (dispatch-sign.py's own rule —
        "a transcript missing one signs an absence" — one rule, two signers); and a requested
        transcript that cannot be written is reported AND returned False, so main() can refuse
        to exit 0 without the artifact the caller asked for."""
        payload = record
        if seed is not None:
            missing = [k for k in cls.FIELDS if record.get(k) is None]
            if missing:
                print(f"verify: transcript not signed — the verdict object is missing {missing}, "
                      "and signing an absence binds nothing (dispatch-sign.py refuses the same)",
                      file=sys.stderr)
                return False
            ed = _load_ed25519()
            sig = ed.signature(cls.canonical(record), seed, ed.publickey(seed))
            payload = {"record": record, "sig_b64": base64.b64encode(sig).decode("ascii")}
        try:
            out = Path(out_ref)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"verify: could not write transcript {out_ref}: {exc}", file=sys.stderr)
            return False
        return True


_canonical_transcript = _Transcript.canonical  # the parity test's name, beside _canonical_dispatch


def _manifest_nc_values(m):
    """What the manifest actually claims for each signed negative-control input (#311).

    nc_artifact_sha256 is derived, not declared: the record signs the CONTENT of the control's
    artifact, so the gate hashes the file the manifest points at rather than trusting a digest the
    same manifest supplies. Unreadable is None here and fails closed at the comparison."""
    nc = m.get("negative_control") or {}
    paths = nc.get("paths")
    digest = None
    art = nc.get("artifact")
    if isinstance(art, str) and art:
        raw, err = read_artifact(m, art)
        if err is None:
            digest = hashlib.sha256(raw).hexdigest()
    return {"nc_paths": sorted(str(x) for x in paths) if isinstance(paths, list) else paths,
            "nc_command": nc.get("command"),
            "nc_artifact_sha256": digest}


def check_dispatch_provenance(m, contract_digest, unit_class, lighting, record_ref, pubkey_ref,
                              no_gh=False, lane=None, execute_nc=False, allow_static_nc=False):
    """13. #135: verify a coordinator-signed dispatch record so a run's contract_digest / unit_class /
    lighting / lane flags (--lane, --no-gh, --execute-nc) can be checked against what the
    coordinator actually authorized. This is a SOUNDNESS
    boundary only when the *verifying key* is trusted — i.e. supplied by an OFF-WORKER context
    (CI/MCP/SDK, or an auditor re-running verify.py with the coordinator's real public key). In the
    native in-session hook the worker controls the key source, so there it is defense-in-depth, not a
    boundary (verify-gate.sh keeps that lane ADVISORY; the durable value is off-worker detection).
      - neither record nor pubkey -> [] (nothing to check).
      - only one of them -> fail-closed (cannot verify).
      - bad signature, an id that names another unit, or a used field the record did not sign / signed
        differently -> fatal (substitution / replay caught).
      - all good -> NOTE (signature verified against the SUPPLIED key)."""
    if not record_ref and not pubkey_ref:
        return []
    if bool(record_ref) != bool(pubkey_ref):
        missing = "--dispatch-record" if pubkey_ref else "--dispatch-pubkey"
        return [f"dispatch provenance half-configured (missing {missing}) — cannot verify; fail-closed (#135)"]
    # W3-03: the KEY's location is what makes the signature mean anything; the record's is named
    # (it is authenticated by that signature, so where it is read from cannot raise its trust).
    key_where, key_read, key_pinned, refused = _Authority.key_source(pubkey_ref, "--dispatch-pubkey")
    if refused:
        return [refused]
    record_where = _Authority.key_source(record_ref, "--dispatch-record")[0]
    try:
        ed = _load_ed25519()
    except Exception as exc:
        return [f"dispatch provenance requested but the Ed25519 verifier is unavailable ({exc}) — fail-closed"]
    try:
        _Transcript.signer()  # the canonical form _canonical_dispatch reads (review P2-2)
    except Exception as exc:
        return [f"dispatch provenance requested but dispatch-sign.py's canonical form is "
                f"unavailable ({exc}) — fail-closed"]
    rec_text, err = read_source(record_ref)
    if err:
        return [f"dispatch record unreadable ({record_ref}): {err}"]
    pub_text, err = read_source(key_read)  # the commit key_source resolved, once
    if err:
        return [f"dispatch pubkey unreadable ({pubkey_ref}): {err}"]
    try:
        envelope = json.loads(rec_text.decode("utf-8"))
        record = envelope["record"]
        sig = base64.b64decode(envelope["sig_b64"], validate=True)  # as run_report/inventory (h409 O-2.2)
        pub = bytes.fromhex(pub_text.decode("utf-8").strip())
    except (ValueError, KeyError, TypeError) as exc:
        return [f"dispatch record / pubkey malformed ({exc})"]
    if not ed.checkvalid(sig, _canonical_dispatch(record), pub):
        return ["dispatch record signature INVALID for the supplied pubkey — not signed by that key "
                "(forged or wrong key); fail-closed (#135)"]
    signed_id = record.get("manifest_id")
    manifest_id = m.get("unit")
    if not signed_id or not manifest_id or signed_id != manifest_id:
        return [f"dispatch record identity {signed_id!r} does not bind this manifest {manifest_id!r} "
                "— a record must name the unit it authorizes, else another unit's record replays (#135)"]
    # Every value the run actually used must be signed AND match — an UNSIGNED field is unbound, so a
    # worker could set it freely; treat that as fail-closed, not a pass.
    for field, used in (("contract_digest", contract_digest), ("unit_class", unit_class),
                        ("lighting", lighting), ("lane", lane)):
        if used is None:
            continue
        signed = record.get(field)
        if signed is None:
            return [f"dispatch record did not sign {field} but the run uses it — unbound value, "
                    "fail-closed (the coordinator must sign every field the gate enforces) (#135)"]
        if signed != used:
            return [f"dispatch substitution: the run used {field}={used!r} but the coordinator signed "
                    f"{signed!r} — the value was tampered (#135)"]
    # The lane flags (review P2). --no-gh WAIVES the GitHub review, so using it unsigned is an
    # unbound waiver; --execute-nc only makes a run stricter, so its absence is what must be bound:
    # a record that signs it requires it. A signed value of either that the run contradicts is a
    # substitution, in whichever direction.
    for field, used, waiver in (("no_gh", bool(no_gh), True),
                                ("execute_nc", bool(execute_nc), False),
                                ("allow_static_nc", bool(allow_static_nc), True)):
        signed = record.get(field)
        if signed is None:
            if used and waiver:
                return [f"dispatch record did not sign {field} but the run uses it — the review "
                        "waiver is unbound, fail-closed (sign it with dispatch-sign.py --no-gh) "
                        "(review P2)"]
            continue
        if not isinstance(signed, bool) or signed != used:
            return [f"dispatch substitution: the run used {field}={used!r} but the coordinator signed "
                    f"{signed!r} — the lane flag was tampered (review P2)"]
    # The negative-control inputs (#311). Optional: a coordinator that could not know them at
    # dispatch time signs none, and they stay bound by base_sha..head_sha alone (#280). Signed,
    # they are the oracle the coordinator chose, and the manifest does not get to swap it.
    claimed = _manifest_nc_values(m)
    for field in ("nc_paths", "nc_command", "nc_artifact_sha256"):
        signed = record.get(field)
        if signed is None:
            continue
        if field == "nc_paths" and isinstance(signed, list):
            signed = sorted(str(x) for x in signed)
        if claimed[field] is None:
            return [f"dispatch record signs {field} but the manifest carries no value for it — the "
                    "coordinator chose the control's inputs and this unit did not use them; "
                    "fail-closed (#311)"]
        if signed != claimed[field]:
            return [f"dispatch substitution: the manifest's {field}={claimed[field]!r} but the "
                    f"coordinator signed {signed!r} — the worker chose its own oracle (#311)"]
    # base_sha (2026-10-26 review): optional, like the control's inputs; signed, the content the
    # control restores is the coordinator's choice and the manifest does not get to move it.
    signed_base = record.get("base_sha")
    if signed_base is not None and signed_base != m.get("base_sha"):
        return [f"dispatch substitution: the manifest's base_sha={m.get('base_sha')!r} but the "
                f"coordinator signed {signed_base!r} — the control's pre-fix content was swapped"]
    advisory = ("" if key_pinned else
                " — ADVISORY: a key the graded worker can swap opens no enforcement lane; the "
                "signature is checked, with no soundness claim (PR #719 review)")
    return ["NOTE: dispatch record signature verified against the supplied key (#135) — a soundness "
            "boundary only if that key is trusted (off-worker: CI/MCP/SDK or an auditor); key: "
            f"{key_where}; record: {record_where} (W3-03){advisory}"]


def check_class_downgrade(m, unit_class, record_ref, pubkey_ref):
    """14. #310: `unit_class` reaches the native in-session gate through ORCA_UNIT_CLASS, and the
    worker owns its own environment. Declaring `report-only` sheds the negative control, the intent
    packet, lighting legality and reviewer_mode in one move — the same manifest that fails seven
    invariants as `mutation` passed every check as `report-only`.

    A signed dispatch record already binds unit_class to what the coordinator authorized, so a
    SUPERVISED downgrade needs nothing here. Unsupervised, the class is a claim, and the one thing
    a worker cannot restate is what base_sha..head_sha actually changes. A report on work that
    touched no production path is the honest shape: it passes, but the verdict says it was
    unsupervised. A `report-only` unit that changed production code is a mutation wearing another
    class's name.

    Shape-unknown fails closed. base_sha and head_sha are worker-supplied too, so "I cannot tell"
    must not pass where "it changed code" fails — otherwise the bypass is just one field along.

    An EMPTY DECLARED RANGE is the sharpest case of that and is refused outright. base_sha ==
    head_sha says "this unit changed nothing", which is an assertion with nothing behind it: the
    gate reads no diff, so there is nothing to measure the class against. A first cut let it pass
    on the reasoning that an empty range changes nothing whatever the ref resolves to — true about
    the DECLARED range, and silent about the work. A worker that changed production code in commit
    C can declare base = head = C and shed every mutation obligation (PR #308 review, P1).
    Removing that branch does not close it either: a pinned equal range diffs empty, so it lands
    on the no-code path anyway. What closes it is requiring a range that is pinned, real and
    NON-DEGENERATE — a report-only unit shows the commit range its report covers, and that range
    contains no code.

    None of this makes the native path sound; it cannot. base_sha and head_sha are the same
    worker's, so a determined unit can name some other doc-only range. That is the #112 result, not
    a gap this check can close: the authority is a signed dispatch record, and the verdict says
    `(unsupervised)` whenever there is none."""
    if _is_mutation(unit_class):
        return []
    if record_ref and pubkey_ref:
        return []  # check_dispatch_provenance binds unit_class to the coordinator's signature
    base, head = m.get("base_sha"), m.get("head_sha")
    if base and head and base == head:
        return [f"{unit_class} unit declares base_sha == head_sha ({base}) and carries no signed "
                "dispatch record. An empty range asserts that this unit changed nothing and gives "
                "the gate no diff to check that against — a claim, not evidence, from the same "
                "worker that chose the class. Name the range the report covers, or have the "
                "coordinator sign the downgrade (#310)"]
    prod, err = _production_changes(base, head)
    if err:
        return [f"{unit_class} unit with no signed dispatch record, and its shape cannot be "
                f"determined: {err}. Pin base_sha and head_sha so the claim can be measured "
                "against the change, or have the coordinator sign the downgrade (#310)"]
    if prod:
        return [f"{unit_class} unit changed code {sorted(prod)} and carries no signed dispatch "
                "record. unit_class arrives from the environment the worker controls, so this "
                "single value drops the negative control, the intent packet, lighting legality "
                "and reviewer_mode from a unit that changed behaviour. Verify it as a mutation, "
                "or have the coordinator sign the downgrade (#310)"]
    return [f"NOTE: {unit_class} (unsupervised) — claimed with no signed dispatch record. "
            "base_sha..head_sha changes prose (docs) only, so the class is consistent with the "
            "change, but nothing off-worker authorized it (#310)"]


def check_replay_request(m, is_mutation, execute_nc, nc_command):
    """Validate requested replay capabilities without entering the executor."""
    if not is_mutation or not execute_nc:
        return []
    nc = m.get("negative_control") or {}
    tool = nc.get("tool")
    if tool not in EXECUTABLE_NC_TOOLS or _Authority.unreplayable_tool(m, nc, tool):
        return [f"--execute-nc: no replay is implemented for negative_control.tool {tool!r} "
                f"— only {list(EXECUTABLE_NC_TOOLS)} can be re-executed here; fail-closed (#255)"]
    _, err = _nc_command(nc, nc_command)
    return [f"--execute-nc: {err}"] if err else []


def verify(manifest_path, contract_source=None, contract_digest=None, repo=None,
           base=None, symbol=None, execute_nc=False, unit_class=None, no_gh=False, lighting=None,
           dispatch_record=None, dispatch_pubkey=None, nc_command=None, lane=None, judged=None,
           retention_pubkey=None, allow_static_nc=False):
    """Return (fatal_errors, notes). fatal_errors non-empty => exit 2. A `judged` dict receives
    the manifest bytes this run loaded (`judged["raw"]`), for the transcript to bind to.
    `retention_pubkey` is the coordinator's trust key for the retention receipt (#608)."""
    m, err = load_manifest(manifest_path)
    if err:
        return None, err
    if judged is not None:
        judged["raw"] = m.raw
    _Authority.ensure(repo)  # a library caller that never ran main(): pin BEFORE the control (F-1)
    is_mut = _is_mutation(unit_class)
    corroborated = bool(contract_source and contract_digest)
    fatal, notes = [], []
    if unit_class is not None and unit_class not in UNIT_CLASSES:
        # An unknown class (a typo, or a class this script predates) must not wedge on a usage
        # error: _is_mutation already fails safe to mutation — say so loudly (#178).
        notes.append(f"NOTE: unknown unit class {unit_class!r} — expected one of "
                     f"{sorted(UNIT_CLASSES)}; failing safe to mutation-strict checks (#178)")
    def collect(checks):
        for run_check in checks:
            try:
                result = run_check()
            except Exception as exc:
                result = [f"malformed manifest: {type(exc).__name__} in a verifier check ({exc})"]
            for line in result:
                (notes if line.startswith("NOTE:") else fatal).append(line)

    # A flag the caller left off falls back to the value a VERIFIED dispatch record signs:
    # omitting --lane against a record signing lane "0" skipped the Lane-0 refusal, and an
    # omitted --lighting skipped the lighting swap check (PR #571 review). Adoption needs a
    # clean provenance verdict; the provenance check below re-verifies with the adopted values,
    # so a record swapped between the two reads fails there as a substitution.
    if dispatch_record and dispatch_pubkey and (lane is None or lighting is None):
        verdict = check_dispatch_provenance(m, contract_digest, unit_class, lighting,
                                            dispatch_record, dispatch_pubkey, no_gh=no_gh,
                                            lane=lane, execute_nc=execute_nc,
                                            allow_static_nc=allow_static_nc)
        rec_text, rec_err = read_source(dispatch_record)
        if all(line.startswith("NOTE:") for line in verdict) and not rec_err:
            try:
                signed = json.loads(rec_text.decode("utf-8"))["record"]
            except (ValueError, KeyError, TypeError):
                signed = {}
            if isinstance(signed, dict):
                lane = signed.get("lane") if lane is None else lane
                lighting = signed.get("lighting") if lighting is None else lighting

    # Admission is read-only. Never construct worktrees, apply patches or run the NC command
    # until the scope, commit identities, signed inputs and evidence snapshot are accepted.
    collect((
        lambda: _Authority.authority_leg(),
        lambda: check_scope(m, contract_source, contract_digest),
        lambda: check_oracle_scope(m, contract_source, contract_digest),
        lambda: check_shas_present(m),
        lambda: check_real_commits(m, is_mut),
        lambda: check_ancestry(m, base),
        lambda: check_base_binding(m, base, execute_nc),
        lambda: check_dispatch_provenance(m, contract_digest, unit_class, lighting,
                                          dispatch_record, dispatch_pubkey,
                                          no_gh=no_gh, lane=lane, execute_nc=execute_nc,
                                          allow_static_nc=allow_static_nc),
        lambda: check_class_downgrade(m, unit_class, dispatch_record, dispatch_pubkey),
        lambda: check_freshness(m),
        lambda: check_commands(m, is_mut, nc_command),
        lambda: check_redaction(m, manifest_path),
        lambda: check_intent(m, is_mut),
        lambda: check_lighting(m, is_mut, lighting, lane),
        lambda: check_reviewer_mode(m, is_mut),
        lambda: check_provenance(m),
        lambda: check_retention_receipt(m, retention_pubkey),
        lambda: check_replay_request(m, is_mut, execute_nc, nc_command),
    ))
    nc_executed = False
    try:
        nc_errs, nc_executed = check_negative_control(m, is_mut, execute_nc and not fatal, nc_command)
        collect((lambda: nc_errs,))
    except Exception as exc:
        fatal.append(f"malformed manifest: {type(exc).__name__} in the negative-control check ({exc})")
    oss_authorized = _Authority.quiet_oss_authorized(contract_source, contract_digest)
    collect((
        lambda: check_review(m, repo, is_mut, no_gh, corroborated, lighting, nc_executed,
                             allow_static_nc=allow_static_nc or (execute_nc and bool(fatal)),
                             oss_authorized=oss_authorized),
        lambda: check_symbol_on_base(symbol, base),
    ))
    notes.extend(_Authority.unexecuted_nc_note(is_mut, nc_executed, fatal))
    return (fatal, notes), None


def _root_arg(flag, value):
    """Validate a root named on the command line. Returns (resolved|None, err|None).

    A root outside a clone is refused for the same reason #267 refuses an out-of-repo artifact:
    an auditor re-derives evidence from a checkout, so `/tmp` is not a root, it is a hiding
    place. Refusing at parse time also keeps the failure a USAGE error (exit 1) rather than a
    verdict on the unit (exit 2) — a misconfigured verifier has not judged anything."""
    if value is None:
        return None, None
    path = Path(value)
    if not path.is_dir():
        return None, f"{flag}: not a directory: {value}"
    resolved = str(path.resolve())
    code, out, _ = _run([_Authority.git_bin(), "-C", resolved, "rev-parse", "--is-inside-work-tree"],
                        env=_Authority.git_env())
    if code != 0 or out.strip() != "true":
        return None, (f"{flag}: '{value}' is not inside a git work tree — evidence no auditor can "
                      "re-derive from a clone is refused (#267)")
    return resolved, None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent evidence-manifest verifier.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--contract-source", default=None,
                    help="AUTHORITATIVE frozen contract (path@ref), from the dispatch record — not the manifest")
    ap.add_argument("--contract-digest", default=None, help="AUTHORITATIVE sha256 of the frozen contract")
    ap.add_argument("--repo", default=None,
                    help="owner/name for the review lookup. REQUIRED on a lane claiming soundness "
                         "(--provenance ci|mcp|sdk|dispatch, or a signed dispatch record + a pinned pubkey); "
                         "elsewhere inferred from origin and recorded as ADVISORY — origin is a "
                         "remote the worker can rewrite (h409 F-2)")
    ap.add_argument("--provenance", default=None,
                    help="ci|mcp|sdk|dispatch asserts the env came from OFF the worker (verify-gate.sh "
                         "forwards ORCA_PROVENANCE). On such a lane the review authority must be "
                         "sound: an explicit --repo, and a gh binary outside any worker-writable "
                         "location — else the review leg fails closed (h409 F-1/F-2)")
    ap.add_argument("--nc-command", default=None,
                    help="AUTHORITATIVE criterion-bound command for --execute-nc, supplied out of "
                         "band by the coordinator. REQUIRED by --execute-nc (#279): the manifest "
                         "and the commands ledger are both worker-written, so neither can "
                         "authorise the other. The manifest must agree with this or the run is "
                         "RED. A unit never chooses what proves it.")
    ap.add_argument("--execute-nc", action="store_true",
                    help="EXECUTE the negative control (#255): apply it in a throwaway worktree at "
                         "head_sha, require the bound command to exit non-zero there and 0 at "
                         "clean head_sha. Requires --nc-command (#279). REQUIRED by default on "
                         "mutation units (#750 C10) and unconditionally in review-waiver lanes "
                         "(--lighting dark-eligible / --no-gh / awaiting-maintainer-merge) (#256)")
    ap.add_argument("--allow-static-nc", action="store_true",
                    help="explicitly waive --execute-nc on an independently GitHub-reviewed "
                         "mutation unit and accept artifact-only negative-control corroboration "
                         "(disclosed as a NOTE; never honored in review-waiver lanes; #750 C10)")
    ap.add_argument("--base", default=None, help="integration base branch (for ancestry)")
    ap.add_argument("--symbol", default=None, help="a unit symbol to grep on the base")
    ap.add_argument("--unit-class", default=None,
                    help="unit class from the dispatch record (mutation|report-only|planning); "
                         "missing/unknown => mutation (fail-safe, with a NOTE) — validated in "
                         "code, not by argparse, so an unknown value cannot wedge the gate (#178)")
    ap.add_argument("--no-gh", action="store_true",
                    help="offline/no-gh lane (merge-serialization.md): review is a local reviewer "
                         "artifact at head_sha, coordinator-attested — set by the coordinator, not the worker")
    ap.add_argument("--lighting", default=None, choices=sorted(LIGHTING_VALUES),
                    help="unit lighting from the dispatch record (lit|dark-eligible); dark-eligible "
                         "waives the independent-review requirement — set by the coordinator, not the worker")
    ap.add_argument("--lane", default=None, choices=["A", "B", "0"],
                    help="unit lane from the dispatch record (A|B|0, gate-classification.md); "
                         "supplied, it binds Lane-0 refusal and dark-eligibility's Lane-A "
                         "requirement — set by the coordinator, not the worker")
    ap.add_argument("--dispatch-record", default=None,
                    help="coordinator-signed dispatch record (path or path@ref) binding "
                         "contract-digest/unit-class/lighting and, when signed, lane/no-gh/"
                         "execute-nc — makes the native hook path sound (#135)")
    ap.add_argument("--dispatch-pubkey", default=None,
                    help="repo-pinned coordinator public key (path or path@ref) that verifies "
                         "--dispatch-record; a committed pubkey is one the worker cannot swap. "
                         "On a --provenance lane only path@<commit id>, or path@<ref> whose final "
                         "target is remote-tracking, is read — at the one commit it resolves to; "
                         "a bare path is the worker's working tree (W3-03)")
    ap.add_argument("--git-dir", default=None,
                    help="run the git/SHA legs (commit existence, ancestry, trees, path@ref "
                         "reads, negative-control worktrees) against the clone at this directory "
                         "instead of the process cwd — for a CHAINED-RUN manifest whose evidence "
                         "and commits live in different repos (#442). Must be inside a git work "
                         "tree or the run is refused; absent, every git leg runs where it always "
                         "did. Coordinator-supplied: the manifest never names the root it is "
                         "judged against")
    ap.add_argument("--evidence-root", default=None,
                    help="resolve and BOUND manifest-relative evidence paths under this directory "
                         "instead of the cwd's git toplevel (#442). The #267 bound is unchanged, "
                         "only re-rooted: an absolute path, or one escaping this root, stays "
                         "REFUSED, and the root must itself be inside a git work tree — evidence "
                         "no auditor can re-derive from a clone is not evidence. NOT implied by "
                         "--git-dir. Once the two roots name different repositories, the SHA "
                         "repo is never consulted for evidence bytes — a same-path blob there is "
                         "not this manifest's evidence — so cross-repo evidence passes only on "
                         "its artifacts[] sha256 pin, read from the evidence root")
    ap.add_argument("--retention-pubkey", default=None, metavar="PATH[@REF]",
                    help="the COORDINATOR's trust key for the provenance retention receipt (#608): "
                         "a path or path@ref, normally .orca/dispatch-pubkey@refs/remotes/origin/main "
                         "in the coordinator's own clone (on a sound lane only path@<commit id> or a ref whose "
                         "final target is remote-tracking, read at one commit, W3-03). Supplied, provenance.retention must name a v1 receipt that "
                         "verifies OFFLINE under THIS key and binds its signed inventory and this "
                         "manifest — a key inside the receipt is never trusted. Absent, a manifest "
                         "that claims the binding (provenance.retention_receipt) fails closed and "
                         "unclaimed provenance stays presence-only")
    ap.add_argument("--transcript-out", default=None, metavar="PATH",
                    help="write the verdict as a machine-readable TRANSCRIPT object (#281/#386): "
                         "unit, manifest path+sha256, the full argument tuple, fatal/notes, exit, "
                         "toolchain, UTC timestamp. Alone it is unsigned (to be wrapped offline by "
                         "dispatch-sign.py sign-transcript); with --transcript-key it is the signed "
                         "{record, sig_b64} envelope run_report.py requires once "
                         ".orca/dispatch-pubkey is committed")
    ap.add_argument("--transcript-key", default=None, metavar="SEED",
                    help="the COORDINATOR's private seed (dispatch-sign.py gen-key) — sign the "
                         "transcript in-process. Requires --transcript-out. Never on the graded "
                         "worker: a worker holding the seed would just self-sign")
    args = ap.parse_args(argv)

    if shutil.which("git") is None:  # the pin proper is _Authority.resolve() below (h409 R2)
        print("dependency: git not on PATH", file=sys.stderr)
        return 1
    seed = None
    if args.transcript_key is not None:
        if args.transcript_out is None:
            print("usage: --transcript-key requires --transcript-out (nothing to sign)", file=sys.stderr)
            return 1
        if args.execute_nc:
            # h409 F-6: the executed control is worker code running as THIS uid, and the seed
            # is open in this process with its path in argv. The two are for different hosts.
            print("usage: --transcript-key cannot be combined with --execute-nc — the control "
                  "runs worker code in the process that holds the seed. Sign after the control, "
                  "in a process that never ran it: --transcript-out alone, then "
                  "dispatch-sign.py sign-transcript; or a second verify.py invocation without "
                  "--execute-nc", file=sys.stderr)
            return 1
        seed, err = _Transcript.seed(args.transcript_key)
        if err:
            print(f"usage: {err}", file=sys.stderr)
            return 1
    roots, root_errs = {}, []
    for flag, value in (("--git-dir", args.git_dir), ("--evidence-root", args.evidence_root)):
        resolved, err = _root_arg(flag, value)
        root_errs.extend([err] if err else [])
        roots[flag] = resolved
    if root_errs:
        for err in root_errs:
            print(f"usage: {err}", file=sys.stderr)
        return 1
    _ROOTS.update(git=roots["--git-dir"], evidence=roots["--evidence-root"])
    _roots_are_split.cache.clear()  # one answer per run, taken before any control executes
    _is_oracle_path.discovery.clear()  # the same: test discovery is read before the control
    # h409 F-1: the review authority is pinned HERE, before any check runs and long before the
    # executed negative control runs worker code — never looked up lazily after it.
    # PR #719 review round 2: a record + key opens the ENFORCEMENT lane (sound, like a provenance
    # lane) only when the key is pinned — a commit id or a ref whose final target is
    # remote-tracking. With a working-tree or local-ref key the worker could have swapped, the run
    # stays on the advisory lane: the signature is still checked, and nothing claims soundness.
    # The documented in-session flows (verify-gate's working-tree pin, an env key) keep working.
    enforcement = bool(args.dispatch_record and args.dispatch_pubkey) and \
        _Authority.key_source(args.dispatch_pubkey, "--dispatch-pubkey")[2]
    repo = _Authority.resolve(args.provenance, enforcement, args.repo)
    # W3-11: the toolchain is hashed BEFORE verify() — before the executed control runs worker
    # code — and again after; a sibling that changed in between is not the verifier that judged.
    toolchain = _Transcript.hash_files()
    judged = {}
    out, load_err = verify(args.manifest, args.contract_source, args.contract_digest,
                           repo, args.base, args.symbol, args.execute_nc,
                           args.unit_class, args.no_gh, args.lighting,
                           args.dispatch_record, args.dispatch_pubkey, args.nc_command,
                           lane=args.lane, judged=judged, retention_pubkey=args.retention_pubkey,
                           allow_static_nc=args.allow_static_nc)
    drift = sorted(name for name, sha in _Transcript.hash_files().items() if sha != toolchain[name])
    drifted = ([f"toolchain changed during this run: {drift} no longer hash as they did when the "
                "verifier started — worker code (the executed control) ran in between, so the "
                "verdict was not reached by the verifier a transcript would name; fail-closed "
                "(W3-11)"] if drift else [])
    if load_err:
        print(f"FAIL: {load_err}", file=sys.stderr)
        for f in drifted:
            print(f"FAIL: {f}", file=sys.stderr)
        print("verify: evidence manifest malformed/unreadable — unit is NOT done", file=sys.stderr)
        fatal, notes, code = [load_err, *drifted], [], 2
    else:
        fatal, notes = out
        fatal = [*fatal, *drifted]
        for n in notes:
            print(n)
        if fatal:
            for f in fatal:
                print(f"FAIL: {f}", file=sys.stderr)
            print(f"verify: {len(fatal)} invariant(s) failed — unit is NOT done", file=sys.stderr)
            code = 2
        else:
            print("verify: OK — all required checks passed")
            code = 0
    if args.transcript_out is not None:
        record = _Transcript.build(args, code, fatal, notes, raw=judged.get("raw"), files=toolchain)
        written = _Transcript.write(args.transcript_out, record, seed)
        if not written and code == 0:
            # A requested-and-missing artifact is fail-closed (#281/#386, round-1 R-3): the verdict
            # stands on stdout, but `--transcript-out X && use X` must never see exit 0 and no X.
            # A RED verdict keeps its own code — 2 already says the unit is not done.
            print("verify: the requested transcript was not written — exit 1 (usage), the verdict "
                  "above stands", file=sys.stderr)
            code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
