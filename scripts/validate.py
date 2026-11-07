#!/usr/bin/env python3
"""
Validate open-fleet against its own architecture (see ARCHITECTURE.md).

Three things are checked:

1. Every mission (skills/<name>/SKILL.md) is a valid agentskills.io skill:
   - name: 1-64 chars, lowercase letters/digits/hyphens, matches its folder
   - description: 1-1024 chars
   - compatibility: optional, 1-500 chars
   - proof: required — doctrine-only | self-run | external-run. Advancing past
     doctrine-only requires proof_evidence: a run-report path that exists. Ten
     unproven missions presented as proven is how the predecessor repo died;
     the honesty is machine-checked here.
   - instruction budget: mission body ≤ 110 + frontmatter ≤ 34 lines, playbooks ≤ 90,
     runtime policies ≤ 160. Doctrine creep gets caught by CI, not by a postmortem. Raise a cap
     only by deliberate edit with a reason in the commit.

2. The three-layer separation holds:
   - Only skills/ contains SKILL.md. A SKILL.md under playbooks/ or runtime/ would
     republish an internal protocol as a discoverable skill — the exact routing
     collision this repo exists to remove.
   - Every name in a mission's "Composes …; rides …" clause resolves to a real
     playbook or runtime policy, and every mission has at least one such
     machine-checkable name (a clause with no backticked names silently no-ops).
     The clause is scanned to the end of its paragraph — an abbreviation ("e.g. ")
     or a capitalized "Rides" cannot truncate or escape the scan.
   - Every `<name>.md` mention in a mission AND in every playbook/runtime policy
     resolves — a rename must not dangle anywhere. Uppercase docs (ARCHITECTURE.md,
     SKILL.md) are exempt; URLs are ignored; case/underscore typos of real protocol
     names and path-prefixed references are flagged.

3. The eval layer (ported from marketingskills) is self-consistent:
   - `evals/routing.json` is valid JSON and has at least one positive example per
     mission.
   - Every `skills/<name>/evals/evals.json` is valid JSON, its `skill_name` matches
     the folder, and each eval has the required fields.

Exit code: 0 if all valid, 1 if any failure, 2 if the skills/ catalog itself is missing.

Spec: https://agentskills.io/specification
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

import importlib.util
import json
import math
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Load the eval validator so `scripts/validate.py` also catches broken eval JSON.
_eval_spec = importlib.util.spec_from_file_location("_eval_validator", ROOT / "scripts" / "eval.py")
_eval_validator = importlib.util.module_from_spec(_eval_spec)
_eval_spec.loader.exec_module(_eval_validator)
_rr_spec = importlib.util.spec_from_file_location(
    "run_report", ROOT / "runtime" / "scripts" / "run_report.py"
)
_run_report = importlib.util.module_from_spec(_rr_spec)
_rr_spec.loader.exec_module(_run_report)
# The count-lint regex engine (RV-D1: implementation detail pushed down to a
# private module; this file keeps one re-export, COUNT_LINT_RE, below).
_cl_spec = importlib.util.spec_from_file_location("_countlint", ROOT / "scripts" / "_countlint.py")
_countlint = importlib.util.module_from_spec(_cl_spec)
_cl_spec.loader.exec_module(_countlint)
# The identity-point similarity engine (#288), pushed down the same way; the gate policy stays here.
_id_spec = importlib.util.spec_from_file_location("_identity", ROOT / "scripts" / "_identity.py")
_identity = importlib.util.module_from_spec(_id_spec)
_id_spec.loader.exec_module(_identity)
# The quarantine matcher (#558): one implementation, shared with preflight and
# its CLI, so the deny-list means the same thing at every gate.
_qc_spec = importlib.util.spec_from_file_location(
    "_quarantine_check", ROOT / "runtime" / "scripts" / "quarantine_check.py"
)
_quarantine = importlib.util.module_from_spec(_qc_spec)
_qc_spec.loader.exec_module(_quarantine)
# The catalog grammar — frontmatter reader and composition grammar — is the quarantine matcher's
# own module, so the CI gate, preflight and the CLI read one composition set (2026-10-23 review,
# P1-9 / P1-10). It lives in runtime/scripts/ because the matcher ships inside every bundle.
_grammar = _quarantine._grammar
SKILLS_DIR = ROOT / "skills"
PLAYBOOKS_DIR = ROOT / "playbooks"
RUNTIME_DIR = ROOT / "runtime"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
PROOF_VALUES = {"doctrine-only", "self-run", "external-run"}
AUTONOMY_VALUES = {"L0", "L1", "L2", "L3", "L4", "L5"}
# agentskills.io allowlist (skills-ref / `agentskills validate`). Repo extras
# are first-class, machine-checked claims — not `metadata:` bags. A fourth
# top-level extra fails this validator (issue #211). skills-ref itself still
# reports the extras as unexpected; that is expected, not a migrate-to-metadata
# prompt.
SPEC_FRONTMATTER_FIELDS = {
    "name",
    "description",
    "license",
    "allowed-tools",
    "metadata",
    "compatibility",
}
# The repo's own machine-checked claims live under the spec's extension point,
# `metadata:` (issue #263). Top level is the spec allowlist and nothing else:
# skills-ref (`agentskills validate`), `package_skill.py`, the claude.ai upload
# path and the Skills API all HARD-ERROR on an unexpected top-level key, so a
# repo extra there makes the catalog unpackageable through Anthropic's own paths.
#
# `unit` … `oracle` are the six-point mission-identity tuple of ARCHITECTURE.md
# made machine-readable (issue #265): declaring it is what makes the identity
# test executable instead of a paragraph, and `identity_collisions()` below
# fails the build when two missions declare the same six.
IDENTITY_KEYS = ("unit", "state_machine", "convergence", "ordering", "parking", "oracle")
METADATA_KEYS = {"proof", "autonomy", "proof_evidence", *IDENTITY_KEYS}
METADATA_VALUE_MAX = 160
# Mutating missions land code; they must ride the SHA-bound evidence protocol so
# completion is never graded on worker narration. Report-only / planning /
# diagnosis missions bind evidence differently and are not in this set.
#
# The set is the declared list other authorities mirror (evidence-manifest.md §3), but it is no
# longer the only way in (2026-10-23 review, P2-20): a mission is mutating when it is listed OR
# when its own Composes/rides clause or DEFERRED READS name a code-landing protocol. A renamed
# code-landing mission therefore still owes both rides, and is told to join the list.
LANDS_CODE = frozenset({"build-change", "remediate-finding", "merge-serialization"})
MUTATING_MISSIONS = {
    "ship-it",
    "clean-sweep",
    "oss-contribute",
    "harden-it",
    "speed-it",
    "modernize-it",
    "prove-it",
    "deflake-it",
    "access-it",
    "pin-it",
    "floor-it",
    "reshape-it",
    "field-test-it",
    "migrate-it",
    "oncall-it",
    "absorb-it",
    "document-it",
    # It writes scripts/orca-vm/ and orca.yaml into the target repo; the 2026-10-23 review
    # found it in no mission class (evidence-manifest.md §3 now lists it as a mutation unit).
    "offload-it",
}
# Instruction budget. The predecessor's mandatory instruction surface hit ~42K
# tokens with no counterpressure; these caps are the counterpressure.
#
# A mission's budget is split, because a whole-file cap prices declarations and
# instructions the same: a mission that spends 30 lines on machine-readable
# frontmatter would have to delete 30 lines of protocol to pay for it. The BODY
# cap is the instruction surface and is ratcheted to the measured catalog
# maximum (110 lines, pin-it) — no mission has headroom, so a protocol line
# costs a protocol line. The FRONTMATTER cap bounds the declarations separately.
# Raising either is a deliberate diff, which is the point.
MISSION_BODY_MAX_LINES = 110
MISSION_FRONTMATTER_MAX_LINES = 34
MISSION_MAX_LINES = MISSION_BODY_MAX_LINES + MISSION_FRONTMATTER_MAX_LINES
PLAYBOOK_MAX_LINES = 90
RUNTIME_MAX_LINES = 160
# A single 166KB line beats a line-count cap; a byte budget (generous headroom over the largest
# real file) also catches instruction surface packed into a few very long lines.
_MAX_BYTES_PER_LINE = 240
MISSION_MAX_BYTES = MISSION_MAX_LINES * _MAX_BYTES_PER_LINE
PLAYBOOK_MAX_BYTES = PLAYBOOK_MAX_LINES * _MAX_BYTES_PER_LINE
RUNTIME_MAX_BYTES = RUNTIME_MAX_LINES * _MAX_BYTES_PER_LINE
# The composition grammar is defined ONCE, in runtime/scripts/_catalog_grammar.py, and
# re-exported here: the orphan test, the mission-guide compose check, bundle.py and
# quarantine_check.py all read that one definition rather than keeping a parallel copy
# (quarantine_check.py used to carry its own COMPOSE_CLAUSE_RE — 2026-10-23 review, §5).
#
# A clause is captured through the END of its paragraph (an "e.g. " cannot truncate it), and
# a mutator's evidence-manifest counts only in a RIDES clause (after `;`, a newline, or the
# start of the document) — not mid-prose and not as a bare Composes mention.
COMPOSE_CLAUSE_RE = _grammar.COMPOSE_CLAUSE_RE
RIDES_CLAUSE_RE = _grammar.RIDES_CLAUSE_RE
BACKTICK_RE = _grammar.BACKTICK_RE
# A DEFERRED READS paragraph (it opens a line): read on entering a phase, never at activation.
DEFERRED_RE = _grammar.DEFERRED_RE
# Any lowercase `<name>.md` mention (pipeline text, parentheticals) must also resolve;
# basenames that fail NAME_RE (ARCHITECTURE.md, SKILL.md) are exempt.
MD_TOKEN_RE = _grammar.MD_TOKEN_RE
compose_clause_backticks = _grammar.compose_clause_backticks
_is_url_md_token = _grammar.is_url_md_token
bare_md_stems = _grammar.bare_md_stems
# Backticked clause names plus bare `<name>.md` tokens anywhere — never a Related-section
# backtick (#216). A further deliberate cut, *not* this helper: the human-guide compose check
# uses `guide_declared_protocol_names` (first sentence of each clause), so a caveat like
# clean-sweep's "not a full `runtime-prove` pass" does not force that protocol into
# `docs/missions/`. Do not collapse the two.
explicit_protocol_refs = _grammar.explicit_protocol_refs


def guide_declared_protocol_names(text):
    """Backticked names a human mission guide must list under ## Composes.

    First sentence of each Composes/rides paragraph only. Later sentences are
    caveats (clean-sweep: "not a full `runtime-prove` pass") and must not
    require that protocol in docs/missions/<name>.md.
    """
    names = []
    for clause in COMPOSE_CLAUSE_RE.findall(text):
        first = re.split(r"\.\s+(?=[A-Z])", clause, maxsplit=1)[0]
        names.extend(BACKTICK_RE.findall(first))
    return names


def md_ref_errors(text, protocols, base=None):
    """Errors for every `<name>.md` token that should be a protocol reference.

    URL tokens (https://…/x.md) are external links, not protocol refs. Uppercase
    docs (ARCHITECTURE.md, SKILL.md) are exempt via NAME_RE — but a case or
    underscore typo of a REAL protocol name must not ride that exemption, and a
    path-prefixed form must not pass on basename alone (the path can lie about
    where the file lives) — protocols are referenced by bare name.

    A `./` or `../` path is relative to the file that holds it (`base`), the way a reader
    follows it: `../../docs/x.md` from a SKILL.md was resolved against the repo root and
    reported dangling (2026-10-23 review, §5). Any other path is repo-root-relative.
    """
    errs = []
    for m in MD_TOKEN_RE.finditer(text):
        tok = m.group(0)
        if _is_url_md_token(text, m):
            continue  # URL — an external link, not a protocol reference
        stem = tok.rsplit("/", 1)[-1][: -len(".md")]
        canon = stem.lower().replace("_", "-")
        if NAME_RE.match(stem):
            if "/" in tok:
                # A path-prefixed PROTOCOL name is the wrong-directory lie
                # (playbooks/sandbox-policy.md). A path to anything else (a run
                # report, a doc) is legitimate — but it must exist.
                if stem in protocols or canon in protocols:
                    errs.append(
                        f"path-prefixed reference: {tok} — reference protocols by "
                        f"bare name (`{stem}` or {stem}.md)"
                    )
                elif not ((base or ROOT) / tok if tok.startswith(("./", "../"))
                          else ROOT / tok).exists():
                    errs.append(f"dangling path: {tok} does not exist")
            elif stem not in protocols:
                errs.append(f"dangling reference: {tok} names no playbook or runtime policy")
        elif canon in protocols:
            errs.append(
                f"case/underscore typo: {tok} — the protocol file is {canon}.md"
            )
    return errs


def known_protocol_names():
    names = set()
    for d in (PLAYBOOKS_DIR, RUNTIME_DIR):
        if d.exists():
            names |= {p.stem for p in d.glob("*.md")}
    return names


# The frontmatter reader is the shared one (runtime/scripts/_catalog_grammar.py). This file's
# own copy read `unit: >-` under `metadata:` as the literal `>-` and cut a plain multi-line
# description at its first line, so the identity gate scored a folded point 0.0 and the length
# caps measured a fragment (2026-10-23 review, P1-9 / P2-16). One reader for every gate now.
parse_frontmatter = _grammar.parse_frontmatter


def read_text_safe(path):
    """Read UTF-8 text. Return (text, None) or (None, error). Never raises.

    One corrupt SKILL.md must not abort validation of the rest of the catalog
    (issue #71 / TODOS.md). Same guard for playbooks/ and runtime/.
    """
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError:
        return None, "unreadable: not valid UTF-8"
    except OSError as err:
        return None, f"unreadable: {err}"


def split_budget(text):
    """(frontmatter lines, body lines) — declarations and instructions priced apart. BOM-tolerant,
    as frontmatter_lines is: a BOM used to price the whole frontmatter as body (2026-10-26 review)."""
    if text.startswith("\ufeff"):
        text = text[1:]
    m = re.match(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", text, re.S)
    if not m:
        return 0, len(text.splitlines())
    return len(m.group(1).splitlines()) + 2, len(text[m.end():].splitlines())


def validate_skill(skill_dir, protocols):
    errors = []
    name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return ["missing SKILL.md"]

    text, read_err = read_text_safe(skill_md)
    if read_err:
        return [read_err]
    data, err = parse_frontmatter(text)
    if err:
        return [f"frontmatter parse error: {err}"]

    if "name" not in data:
        errors.append("missing 'name' field")
    elif not isinstance(data["name"], str):
        errors.append("name must be a string, got a mapping or sequence")
    else:
        n = data["name"]
        if not (1 <= len(n) <= 64):
            errors.append(f"name length {len(n)} out of 1-64")
        if not NAME_RE.match(n):
            errors.append(f"name '{n}' invalid (lowercase letters/digits/hyphens only)")
        if n != name:
            errors.append(f"name '{n}' does not match folder '{name}'")

    if "description" not in data:
        errors.append("missing 'description' field")
    elif data["description"] == _grammar.OBJECT or not isinstance(data["description"], str):
        # The sentinel is a sequence; a nested mapping comes back as a dict (PR #707 review).
        errors.append("description must be a string, got a mapping or sequence")
    elif not (1 <= len(data["description"]) <= 1024):
        errors.append(f"description length {len(data['description'])} out of 1-1024")
    for key in ("license", "allowed-tools"):
        if key in data and (data[key] == _grammar.OBJECT or not isinstance(data[key], str)):
            errors.append(f"{key} must be a string, got a mapping or sequence")

    extras = set(data) - SPEC_FRONTMATTER_FIELDS
    if extras:
        errors.append(
            "unexpected top-level frontmatter fields "
            + ", ".join(f"'{k}'" for k in sorted(extras))
            + " — the spec allowlist is "
            + str(sorted(SPEC_FRONTMATTER_FIELDS))
            + "; repo claims belong under 'metadata:' (issue #263)"
        )

    meta = data.get("metadata")
    if meta is None:
        errors.append(
            "missing 'metadata:' block (proof, autonomy, and the six identity keys live there)"
        )
        meta = {}
    elif not isinstance(meta, dict):
        errors.append("metadata must be a map of string keys to string values")
        meta = {}
    else:
        unknown = set(meta) - METADATA_KEYS
        if unknown:
            errors.append(
                "unexpected metadata keys "
                + ", ".join(f"'{k}'" for k in sorted(unknown))
                + f" — allowed: {sorted(METADATA_KEYS)}"
            )
        for key, value in sorted(meta.items()):
            # The shared reader hands back a nested map as a dict and a `- item` sequence as the
            # OBJECT sentinel; the spec's metadata is a map of strings to STRINGS, and an identity
            # point that is a list would compare as the sentinel's text (2026-10-26 review).
            if not isinstance(value, str) or not value.strip() or value == _grammar.OBJECT:
                errors.append(f"metadata.{key} must be a non-empty string")
            elif len(value) > METADATA_VALUE_MAX:
                errors.append(
                    f"metadata.{key} is {len(value)} chars > {METADATA_VALUE_MAX} "
                    "— the tuple is a claim, not a paragraph"
                )
        # The shared reader reads a map nested under a metadata key as a dict; it is reported
        # above and read as empty below, never handed to a check that expects a string.
        meta = {k: (v if isinstance(v, str) and v != _grammar.OBJECT else "") for k, v in meta.items()}

    # Six-point mission identity (ARCHITECTURE.md). Each point is declared, so
    # "is this a mission or a mode of another?" is answered by a diff, not a memo.
    for key in IDENTITY_KEYS:
        if not (meta.get(key) or "").strip():
            errors.append(
                f"missing metadata.{key} — all six identity points "
                f"{list(IDENTITY_KEYS)} are required (ARCHITECTURE.md)"
            )
    errors.extend(identity_point_length_errors(meta))

    if "compatibility" in data:
        c = data["compatibility"]
        if c == "<object>":
            errors.append("compatibility must be a string (1-500 chars), got a mapping")
        elif not (1 <= len(c) <= 500):
            errors.append(f"compatibility length {len(c)} out of 1-500")

    # proof status: honest by construction — no mission presents itself as proven
    # without a run report on disk
    proof = meta.get("proof")
    if proof is None:
        errors.append("missing 'proof' field (doctrine-only | self-run | external-run)")
    elif proof not in PROOF_VALUES:
        errors.append(f"proof '{proof}' invalid (want one of {sorted(PROOF_VALUES)})")
    elif proof != "doctrine-only":
        evidence = meta.get("proof_evidence", "")
        ev_path = (ROOT / evidence).resolve() if evidence else None
        runs_dir = (ROOT / "docs" / "runs").resolve()
        if (
            not ev_path
            or not ev_path.is_relative_to(runs_dir)
            or ev_path.suffix != ".md"
            or not ev_path.is_file()
        ):
            errors.append(
                f"proof '{proof}' requires proof_evidence: a docs/runs/*.md run report that exists"
            )
        else:
            # content correlation: the report must be THIS mission's run — not merely a file that
            # exists, and not another mission's report that mentions this one in prose (#133). The
            # coordinator names a run report after its mission, so require the name both as a
            # hyphen-delimited token in the filename AND in the report body.
            name = data.get("name") or ""
            named_in_file = bool(name and re.search(rf"(?:^|-){re.escape(name)}(?:-|$)", ev_path.stem))
            report, _ = read_text_safe(ev_path)  # None on unreadable / non-UTF-8 — never raises
            named_in_body = bool(name and report and name in report)
            if not (named_in_file and named_in_body):
                errors.append(
                    f"proof '{proof}': proof_evidence {evidence} must be mission '{name}'s run report "
                    f"— name the mission in the filename (docs/runs/<date>-{name}-*.md) and the body"
                )
            # …and the report has to be BOUND, not merely named (issue #259): a
            # RUN: header, a manifest inside the run's own directory, and an
            # inventory that re-hashes at the commit it was computed at.
            errors.extend(_run_report.check_report(evidence, name, proof, ROOT))

    # autonomy level (Osmani L0-L5): a first-class, machine-readable claim sibling to
    # proof — the level a mission safely runs at, gated by how cheaply it is verified.
    autonomy = meta.get("autonomy")
    if autonomy is None:
        errors.append("missing 'autonomy' field (L0-L5)")
    elif autonomy not in AUTONOMY_VALUES:
        errors.append(f"autonomy '{autonomy}' invalid (want one of {sorted(AUTONOMY_VALUES)})")

    fm_lines, body_lines = split_budget(text)
    if body_lines > MISSION_BODY_MAX_LINES:
        errors.append(
            f"instruction budget: {body_lines} body lines > {MISSION_BODY_MAX_LINES} "
            "(mission cap; frontmatter is budgeted separately)"
        )
    if fm_lines > MISSION_FRONTMATTER_MAX_LINES:
        errors.append(
            f"frontmatter budget: {fm_lines} lines > {MISSION_FRONTMATTER_MAX_LINES} "
            "(declarations cap)"
        )
    load, _parts = transitive_load(skill_dir, protocols)
    if load > MISSION_MAX_LOAD_TOKENS:
        errors.append(
            f"activation load: ~{load} tokens > {MISSION_MAX_LOAD_TOKENS} — SKILL.md plus "
            "every doc its Composes/rides clause makes mandatory. Move a phase's doc behind "
            "a 'read <doc> when entering <phase>' cue instead of raising the cap"
        )
    nbytes = len(text.encode("utf-8"))
    if nbytes > MISSION_MAX_BYTES:
        errors.append(
            f"instruction budget: {nbytes} bytes > {MISSION_MAX_BYTES} (mission byte cap)"
        )

    # architecture: every playbook/runtime a mission says it Composes/rides must exist,
    # and there must be at least one such name — a clause the regex can't see into
    # (bare directory pointers, prose) would otherwise pass with zero checks.
    clause_refs = compose_clause_backticks(text)
    for ref in clause_refs:
        if ref not in protocols:
            errors.append(
                f"dangling composition: `{ref}` names no playbook or runtime policy"
            )
    if not clause_refs:
        errors.append(
            "no machine-checkable composition: the Composes/rides clause must name "
            "at least one playbook or runtime policy in backticks"
        )
    # A misspelt clause token (`Build-Change`, `build_change`, `playbooks/build-change`) was
    # neither resolved nor flagged; the `.md` spellings always were (2026-10-23 review, P2-18).
    errors.extend(_grammar.clause_token_typos(text, protocols))
    errors.extend(deferred_read_errors(text, protocols))
    flat = re.sub(r"\s+", " ", text.lower())
    pack_ok = False
    for stmt in re.findall(r"pack:\s*([^.]*)", flat):
        if "never co-mount" not in stmt:
            continue
        head = stmt.split("—")[0].split("(")[0].strip()
        head = re.sub(r"^(?:exactly one of|one of)\s+", "", head)
        names = [t.strip() for t in re.split(r"[|,/]", head) if t.strip()]
        if names and all(n in ("matt", "addy", "gstack") for n in names):
            pack_ok = True
            break
    if not pack_ok:
        errors.append(
            "no worker-pack statement: state the one upstream pack a worker TASK "
            "loads (`pack: one of matt | addy | gstack — never co-mount`) — the "
            "one-router-per-worker rule (AGENTS.md) was prose-only until the full review"
        )
    ride_refs = [
        ref
        for clause in RIDES_CLAUSE_RE.findall(text)
        for ref in BACKTICK_RE.findall(clause)
    ]
    lands = code_landing_refs(text)
    mutating = name in MUTATING_MISSIONS or bool(lands)
    if lands and name not in MUTATING_MISSIONS:
        errors.append(
            f"composes code-landing protocol(s) {lands} but is not in MUTATING_MISSIONS — a "
            "mission that lands code is a mutation unit: list it there and in "
            "evidence-manifest.md §3 (2026-10-23 review, P2-20)"
        )
    if mutating and "evidence-manifest" not in ride_refs:
        errors.append(
            "mutating mission must ride `evidence-manifest` in a rides clause "
            "(SHA-bound definition of done; a Composes mention alone does not count)"
        )
    if mutating and "sandbox-policy" not in ride_refs:
        errors.append(
            "mutating mission must ride `sandbox-policy` in a rides clause "
            "(least-privilege worker profiles; six mutating missions omitted it "
            "entirely until the full review caught the omission by grep)"
        )

    # every lowercase `<name>.md` mention must resolve (catches renames outside the clause)
    errors.extend(md_ref_errors(text, protocols, skill_md.parent))

    return errors


def deferred_read_errors(text, protocols):
    """A DEFERRED READ is a declaration too: the quarantine gate requires it to exist, so a
    backticked one that names nothing is a dangling composition, not prose (a `name.md` one is
    already read by md_ref_errors)."""
    return [
        f"dangling deferred read: `{ref}` names no playbook or runtime policy"
        for para in DEFERRED_RE.findall(text)
        for ref in BACKTICK_RE.findall(para)
        if ref not in protocols
    ]


def code_landing_refs(text):
    """Code-landing protocols a mission names in its own clause or DEFERRED READS (P2-20).

    Direct names only: following playbooks transitively would make every report-only mission
    "mutating" (review-it reaches build-change through acceptance-review's calls).
    """
    named = (_grammar.clause_refs(text) | _grammar.deferred_declared(text)
             | _grammar.deferred_words(text))
    return sorted(named & LANDS_CODE)


def check_protocol_doc_refs(protocols):
    """Playbooks and runtime policies cross-reference each other by `<name>.md`;
    a rename or deletion must not dangle there either (missions are covered by
    validate_skill — without this pass, only skills/ is guarded). The instruction
    budget is enforced on the same walk."""
    failures = []
    caps = {PLAYBOOKS_DIR: PLAYBOOK_MAX_LINES, RUNTIME_DIR: RUNTIME_MAX_LINES}
    byte_caps = {PLAYBOOKS_DIR: PLAYBOOK_MAX_BYTES, RUNTIME_DIR: RUNTIME_MAX_BYTES}
    for d in (PLAYBOOKS_DIR, RUNTIME_DIR):
        if not d.exists():
            continue
        for f in sorted(d.glob("*.md")):
            text, read_err = read_text_safe(f)
            if read_err:
                failures.append(f"{f.relative_to(ROOT)}: {read_err}")
                continue
            for e in md_ref_errors(text, protocols, f.parent):
                failures.append(f"{f.relative_to(ROOT)}: {e}")
            if d == PLAYBOOKS_DIR:
                packs = {
                    {"mattpocock": "matt", "garrytan": "gstack",
                     "addyosmani": "addy"}.get(found, found)
                    for found in re.findall(
                        r"\b(mattpocock|matt|addyosmani|addy|garrytan|gstack)\b",
                        text.lower())
                }
                if len(packs) > 1:
                    failures.append(
                        f"{f.relative_to(ROOT)}: one-router rule: names {sorted(packs)} — "
                        "a playbook draws on one upstream router pack; state any second "
                        "technique as fleet rules in the body, never as a second loaded pack"
                    )
            lines = len(text.splitlines())
            if lines > caps[d]:
                failures.append(
                    f"{f.relative_to(ROOT)}: instruction budget: {lines} lines > "
                    f"{caps[d]} ({d.name} cap)"
                )
            nbytes = len(text.encode("utf-8"))
            if nbytes > byte_caps[d]:
                failures.append(
                    f"{f.relative_to(ROOT)}: instruction budget: {nbytes} bytes > "
                    f"{byte_caps[d]} ({d.name} byte cap)"
                )
    return failures


# Repo content is what git TRACKS: an untracked local dot-dir (.venv, .tox, a tool's cache) is not
# repo content, a TRACKED dot-dir (.github, .claude-plugin) is — and only git knows which. The scan
# uses git ls-files when the root is a work tree, and a filesystem heuristic otherwise (synthetic tests).
_LAYER_SCAN_SKIP = {".git", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _tracked_skill_mds(root):
    """Relative paths of git-TRACKED SKILL.md files, or None if root is not the root of a git work
    tree (a synthetic test dir, or a temp dir nested inside an unrelated repo → filesystem fallback)."""
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10)
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != Path(root).resolve():
            return None
        r = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return [Path(x) for x in r.stdout.split("\0") if x and Path(x).name == "SKILL.md"]


def check_lower_layer_frontmatter(root=None):
    """No file under playbooks/ or runtime/ may carry YAML frontmatter (#305).

    AGENTS.md has said "playbooks and runtime policies are plain Markdown with no frontmatter"
    since the layer rule was written, and nothing enforced it — a playbook handed frontmatter
    passed every gate. That sentence was doctrine wearing a mechanism's clothes, which is the
    exact shape this validator exists to refuse.

    Frontmatter is what makes a file DISCOVERABLE: it is where `name:` and `description:` live,
    and a host that indexes a directory reads it. A playbook is meant to be called by name, never
    matched by a router, so the separation is only real while the lower layers stay unindexable.
    """
    root = root or ROOT
    offenders = []
    for layer in ("playbooks", "runtime"):
        base = root / layer
        if not base.is_dir():
            continue
        for md in sorted(base.rglob("*.md")):
            text = md.read_text(encoding="utf-8", errors="replace")
            # Frontmatter is an opening `---` on line 1 and a closing one later. A horizontal
            # rule mid-document is not frontmatter, and neither is a `---` on line 1 with no
            # close — that is malformed, and calling it frontmatter would be a false red.
            # parse_frontmatter is the repo's own reader, so "what counts as frontmatter" has
            # exactly one definition — including its BOM and CRLF tolerance: a BOM (U+FEFF) before `---`
            # opening used to fail a `startswith("---\n")` pre-check and escape this gate while a
            # host that strips the BOM still indexed it (2026-10-23 review, §5).
            block, err = parse_frontmatter(text)
            if block is not None and not err:
                offenders.append(str(md.relative_to(root)))
    return offenders


def check_hidden_missions(root=None):
    """Refuse a SKILL.md under a `_`- or `.`-prefixed skills/ directory (2026-10-23 review, P2-19).

    Every gate here skips those directories as "not a mission", but the `skills/*/SKILL.md`
    globs in eval.py, bundle.py's input check, install.yml and the agentskills loop pick them
    up, so a `skills/_draft/` with a 404-line body and no metadata passed the build. A draft
    lives outside skills/; a SKILL.md inside it is either a mission (and validated as one) or
    nothing — never a mission nobody checks.
    """
    skills_dir = (root or ROOT) / "skills"
    if not skills_dir.is_dir():
        return []
    return [
        f"skills/{d.name}/SKILL.md — a `_`/`.` prefix skips every catalog rule while installers "
        "and indexers still read it; rename it to a validated mission or move it out of skills/"
        for d in sorted(skills_dir.iterdir())
        if d.is_dir() and d.name.startswith((".", "_")) and os.path.lexists(d / "SKILL.md")
    ]


def check_layer_separation(root=None):
    """Only skills/<name>/ may hold a SKILL.md. AGENTS.md states the rule repo-wide, so the scan is
    repo-wide too — a stray SKILL.md in docs/, .github/, .claude-plugin/, or the repo root
    auto-triggers just as badly as one in playbooks/ or runtime/.

    Tracked AND untracked (#305). This was `git ls-files` alone, so an UNTRACKED `SKILL.md` under
    `playbooks/` passed every gate — and the host does not care whether a file is committed. On a
    symlinked checkout, which is the trial path the README recommends first, that file activates.
    The walk is the authority now and the tracked list only adds to it, so a tracked file inside a
    normally-skipped directory is still in scope. Untracked local dot-dirs (.venv/.tox) and caches
    stay out: they are not repo content on any checkout."""
    root = root or ROOT  # resolve at call time so a monkeypatched validate.ROOT is honored
    candidates = []
    for p in root.rglob("SKILL.md"):
        segs = p.relative_to(root).parts[:-1]
        if any(d in _LAYER_SCAN_SKIP for d in segs):
            continue
        if any(d.startswith(".") and d != ".claude-plugin" for d in segs):
            continue  # untracked local dot-dir (.venv/.tox/.greptile-internal/…) — not repo content
        candidates.append(p.relative_to(root))
    for rel in _tracked_skill_mds(root) or []:
        if rel not in candidates:
            candidates.append(rel)
    leaks = []
    for rel in candidates:
        parts = rel.parts
        if parts[0] == "skills" and len(parts) == 3:
            continue  # skills/<name>/SKILL.md — the one discoverable form
        leaks.append(str(rel))
    return sorted(leaks)


# Transitive activation load (issue #276). The line/byte caps above bound each
# FILE; nothing bounded what a mission makes a coordinator read on activation:
# its SKILL.md, every playbook and runtime doc named in its Composes/rides
# clause, and every repo-root doc it links. The current figures are NOT written
# here: load_report() below computes them, ARCHITECTURE.md publishes them from a
# generated block, and a hand-typed copy is how that table drifted twice (#303).
# What is stable enough to state: every mission is several times what
# agentskills.io recommends per activated skill, and the predecessor died of the
# same shape at ~42K.
#
# The cap is a RATCHET, not the recommendation: set at the catalog's measured
# maximum plus the declared headroom every mission's own budget carries
# (scripts/mission-load-budgets.json), and lowered only by real restructuring
# (per-phase "read <doc> when entering X" cues instead of a single read-everything
# compose clause). Naming the gap honestly and freezing it beats a 5K cap that
# would red every mission on day one and be raised by lunchtime.
#
# It was the bare maximum, 34,000, until 2026-10-26. ship-it then sat 7 tokens
# under it, so one sentence added to any doc ship-it loads failed this gate in an
# unrelated PR and cost a compress-or-defer round trip. 35,000 is the heaviest
# load plus the same 2.5% every mission's budget gets, rounded up to the step.
TOKENS_PER_BYTE = 0.25  # the crude bytes/4 estimate the docs/reviews/2026-09-10-review.md measurement used
MISSION_MAX_LOAD_TOKENS = 35_000
ROOT_DOC_RE = re.compile(r"\]\((?:\.\./)+([A-Z][A-Z0-9_.-]*\.md)\)")


def _repo_rel(path):
    """Repo-relative when the path is inside ROOT, absolute otherwise.

    A fixture skill dir lives in a temp tree while the protocols it composes are
    the real ones; `Path.relative_to` raises across that boundary.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def transitive_load(skill_dir, protocols=None):
    """(tokens, {path: tokens}) a coordinator reads to activate this mission.

    SKILL.md + every playbook/runtime doc its Composes/rides clause names + every
    repo-root doc it links (ARCHITECTURE.md and friends). One hop: what a doc
    itself references is the coordinator's on-demand read, not activation load.
    """
    skill_md = skill_dir / "SKILL.md"
    text, err = read_text_safe(skill_md)
    if err or text is None:
        return 0, {}
    parts = {f"skills/{skill_dir.name}/SKILL.md": len(text.encode("utf-8"))}
    protocols = protocols if protocols is not None else known_protocol_names()
    # Only what the Composes/rides clause makes MANDATORY. A protocol named in
    # prose ("see `mission-chaining.md`") is an on-demand pointer, not activation
    # load — counting it would inflate the number and blur what the cap is for.
    # The same set the quarantine gate starts from (P1-10): clause backticks AND clause `name.md`.
    mandatory = _grammar.clause_refs(text)
    for name in sorted(mandatory):
        if name not in protocols:
            continue
        for base in (PLAYBOOKS_DIR, RUNTIME_DIR):
            doc = base / f"{name}.md"
            if doc.is_file():
                body, doc_err = read_text_safe(doc)
                if not doc_err and body is not None:
                    parts[_repo_rel(doc)] = len(body.encode("utf-8"))
                break
    for root_doc in sorted(set(ROOT_DOC_RE.findall(text))):
        doc = ROOT / root_doc
        if doc.is_file():
            body, doc_err = read_text_safe(doc)
            if not doc_err and body is not None:
                parts[root_doc] = len(body.encode("utf-8"))
    tokens = {path: round(n * TOKENS_PER_BYTE) for path, n in parts.items()}
    return sum(tokens.values()), tokens


def load_report(root=None):
    """[(mission, tokens)] descending — the activation-load table."""
    skills_dir = (root or ROOT) / "skills"
    protocols = known_protocol_names()
    rows = []
    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith((".", "_")):
            continue
        if not (skill_dir / "SKILL.md").is_file():
            continue
        total, _parts = transitive_load(skill_dir, protocols)
        rows.append((skill_dir.name, total))
    rows.sort(key=lambda row: (-row[1], row[0]))
    return rows


def check_load_budgets(root=None):
    """Failures against scripts/mission-load-budgets.json, the per-mission ratchet under the cap.

    One catalog-wide cap bounded only the heaviest mission; the other 21 could grow by thousands
    of tokens with nothing noticing (2026-10-23 review, section 5). Each mission now carries its
    own budget: over it fails, and so does a budget more than `max_slack` above the measured load
    plus the file's declared `headroom` (a fraction; absent means none), so a shrink is banked by
    lowering the budget instead of becoming silent headroom. Headroom is declared, never drift: with
    none, a mission at its budget failed on the next sentence any doc it loads gained (ship-it sat
    7 tokens under on 2026-10-26). A missing or malformed file fails closed: no budgets must never
    read as no limits.
    """
    path = (root or ROOT) / "scripts" / "mission-load-budgets.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        budgets, step, slack = data["budgets"], int(data["step"]), int(data["max_slack"])
        headroom = data.get("headroom", 0)
        if not isinstance(budgets, dict) or step <= 0 or slack < 0:
            raise ValueError("budgets must be an object, step positive, max_slack non-negative")
        if isinstance(headroom, bool) or not isinstance(headroom, (int, float)) \
                or not 0 <= headroom < 0.1:
            raise ValueError("headroom must be a fraction of the load, at least 0 and under 0.1")
    except (OSError, ValueError, KeyError, TypeError) as err:
        return [f"{_repo_rel(path)}: unreadable ({type(err).__name__}: {err}) — every mission "
                "needs a budget; a missing file is not 'no limits'"]
    failures = []
    measured = dict(load_report(root))
    for name, load in sorted(measured.items()):
        budget = budgets.get(name)
        line = math.ceil(load * (1 + headroom))  # the load plus its declared headroom
        suggested = min(-(-line // step) * step, MISSION_MAX_LOAD_TOKENS)
        if not isinstance(budget, int) or isinstance(budget, bool):
            failures.append(f"{name}: no integer budget (measured ~{load} tokens; add {suggested})")
        elif budget > MISSION_MAX_LOAD_TOKENS:
            failures.append(f"{name}: budget {budget} is above the {MISSION_MAX_LOAD_TOKENS} cap")
        elif load > budget:
            failures.append(
                f"{name}: activation load ~{load} tokens > its budget {budget} — move a phase's "
                "doc behind a 'read <doc> when entering <phase>' cue, or raise the budget in a "
                "commit that says why")
        elif budget - line > slack:
            plus = f" plus its {headroom:.1%} headroom (~{line})" if headroom else ""
            failures.append(f"{name}: budget {budget} sits {budget - line} tokens above the "
                            f"measured ~{load}{plus} (max slack {slack}) — lower it to {suggested}")
    for name in sorted(set(budgets) - set(measured)):
        failures.append(f"{name}: a budget for a mission that is not in skills/")
    return failures


# Identity-tuple comparison (#288). The similarity engine — tokenizer hookup, concept table,
# negation polarity, containment — lives in scripts/_identity.py (pushed down like the count-lint
# engine, RV-D1); this module keeps the gate POLICY below and re-exports the three functions it
# and its tests call.
_identity.EVAL = _eval_validator
_identity_tokens = _identity.identity_tokens
_point_similarity = _identity.point_similarity
_identity_sims = _identity.identity_sims

# A point is one sentence about one property. A kitchen-sink point would CONTAIN most other
# missions' points (containment, below, reads the smaller side), so its length is capped.
IDENTITY_POINT_MAX_TOKENS = 20
IDENTITY_POINT_SAME = 0.85
# Six points that are each merely SIMILAR still describe one mission twice. A synonym swap scores
# ~0.67 a point — under the 0.85 bar on every one of them, and a duplicate all the same (#288).
#
# A paraphrase leaves NO point on which the two missions diverge — some points restated, some left
# alone, none of them actually different. That is the signature, and it is what ARCHITECTURE.md
# already implies: differing on one point is legal-but-surfaced (a WARN) and differing on two is
# silent, so a pair with no divergent point at all is one mission twice, however its words are
# arranged. Neither the mean nor the single weakest point works here — a five-of-six match averages
# high while being a legitimate distinction, and a paraphraser can rewrite one point heavily.
#
# Similarity is CONTAINMENT (shared / size of the smaller set), not Jaccard: Jaccard's union
# denominator let filler padding ("…, with care and rigour across every relevant consideration")
# dilute a verbatim restatement below this bar. Padding cannot shrink the smaller side. Measured
# 2026-10-14 over the live catalog (22 missions, 231 pairs): the closest pair (clean-sweep /
# oss-contribute) has 2 of 6 points at or above 0.5 and none of the rest above 0.45, so the
# all-six rule keeps wide clearance.
IDENTITY_POINT_NEAR = 0.5
# The all-six rule escaped on ONE point (2026-10-23 review, P2-17): reword five points within the
# concept table and the sixth with words outside it, and that point scores 0.0 — five near, no
# error, and no WARN either (the WARN counts SAME points, and reworded ones are only near). Five
# near points of which at least one is merely reworded is now the paraphrase signature too. Five
# SAME points plus one far point stays the legal, surfaced WARN, and two far points stay silent:
# both are ARCHITECTURE.md's own rules, and a lexical gate cannot tell a reworded point from a
# genuinely different one, so a paraphrase that rewords two or more points out of the table
# still passes. The live catalog's closest pair has 2 near points, so this keeps clearance.
IDENTITY_PARAPHRASE_MIN_NEAR = 5


def identity_point_length_errors(meta):
    """Identity points over IDENTITY_POINT_MAX_TOKENS content tokens."""
    errors = []
    for key in IDENTITY_KEYS:
        value = meta.get(key)
        if isinstance(value, str):
            n = len(_identity_tokens(value))
            if n > IDENTITY_POINT_MAX_TOKENS:
                errors.append(
                    f"metadata.{key}: {n} content words > {IDENTITY_POINT_MAX_TOKENS} — an "
                    "identity point is one property in one sentence; a kitchen-sink point "
                    "reads as containing every other mission's"
                )
    return errors


def identity_collisions(root=None):
    """Mission pairs that declare the same six identity points.

    ARCHITECTURE.md: two workflows are the same mission only if they share ALL
    six. So the executable form of that test is — no pair may match on six.
    A pair matching on five is reported as a WARN: legal, but it is the shape
    that the access-it / field-test-it / pin-it argument had to be made for, so
    it should never pass unnoticed.
    """
    skills_dir = (root or ROOT) / "skills"
    tuples = {}
    for skill_dir in sorted(skills_dir.iterdir()):
        skill_md = skill_dir / "SKILL.md" if skill_dir.is_dir() else None
        if not skill_md or not skill_md.exists():
            continue
        text, read_err = read_text_safe(skill_md)
        if read_err:
            continue
        data, err = parse_frontmatter(text)
        if err or not isinstance(data, dict):
            continue
        meta = data.get("metadata")
        if isinstance(meta, dict) and all(
                isinstance(meta.get(k), str) and meta[k] for k in IDENTITY_KEYS):
            tuples[skill_dir.name] = tuple(meta[k] for k in IDENTITY_KEYS)
    errors, warnings = [], []
    names = sorted(tuples)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            same = [
                key
                for key, va, vb in zip(IDENTITY_KEYS, tuples[a], tuples[b], strict=True)
                if _point_similarity(va, vb) >= IDENTITY_POINT_SAME
            ]
            sims = _identity_sims(tuples[a], tuples[b])
            near = sum(1 for value in sims if value >= IDENTITY_POINT_NEAR)
            mean = sum(sims) / len(sims) if sims else 0.0
            if len(same) == len(IDENTITY_KEYS):
                errors.append(
                    f"{a} and {b} declare the same six identity points — "
                    "one mission with two names (ARCHITECTURE.md); merge them or "
                    "state which point actually differs"
                )
            elif near == len(IDENTITY_KEYS):
                restated = [k for k, value in zip(IDENTITY_KEYS, sims, strict=True)
                            if value < IDENTITY_POINT_SAME]
                errors.append(
                    f"{a} and {b} restate one identity: all {len(IDENTITY_KEYS)} points are at "
                    f"least similar (mean {mean:.2f}), with {restated} merely reworded rather than "
                    "different. A paraphrase is not a distinction — there is no point on which "
                    "these two missions actually diverge. Merge them, or make one point genuinely "
                    "differ and say so in ARCHITECTURE.md (#288)"
                )
            elif near >= IDENTITY_PARAPHRASE_MIN_NEAR and len(same) < near:
                far = [k for k, value in zip(IDENTITY_KEYS, sims, strict=True)
                       if value < IDENTITY_POINT_NEAR]
                restated = [k for k, value in zip(IDENTITY_KEYS, sims, strict=True)
                            if IDENTITY_POINT_NEAR <= value < IDENTITY_POINT_SAME]
                errors.append(
                    f"{a} and {b} restate {near} of {len(IDENTITY_KEYS)} identity points "
                    f"({restated} reworded, mean {mean:.2f}) and diverge only on {far}. A "
                    "one-point distinction is legal when the shared points are stated as shared "
                    "(the surfaced WARN), not paraphrased: rewording five points and moving one "
                    "out of the gate's vocabulary is how a restatement passes. Merge them, or "
                    "state the shared points in the same words and argue the difference in "
                    "ARCHITECTURE.md (#288; 2026-10-23 review, P2-17)"
                )
            elif len(same) == len(IDENTITY_KEYS) - 1:
                differs = [k for k in IDENTITY_KEYS if k not in same]
                warnings.append(
                    f"{a} and {b} differ on only {differs[0]} — legal, but the "
                    "argument for keeping both belongs in ARCHITECTURE.md"
                )
    return errors, warnings


# Proof ratchet (full review): the catalog stood at 22 missions with 3 proven
# past doctrine-only and none external — the predecessor died at 12 with 2
# proven (ARCHITECTURE.md). Breadth may grow again only when proof pays for
# it: each mission beyond the base total must be offset by one more mission
# proven past doctrine-only than the base had. Raising either base is a
# deliberate, reasoned edit in the diff that earns it — never drift.
CATALOG_BASE = (22, 3)  # (missions, proven past doctrine-only) at the full review


def check_proof_ratchet(root=None):
    """Fail when catalog breadth outruns proof past the ratchet above."""
    skills_dir = (root or ROOT) / "skills"
    total = proven = 0
    if skills_dir.exists():
        for skill_dir in sorted(skills_dir.iterdir()):
            skill_md = skill_dir / "SKILL.md" if skill_dir.is_dir() else None
            if not skill_md or not skill_md.exists():
                continue
            text, read_err = read_text_safe(skill_md)
            if read_err:
                continue
            data, err = parse_frontmatter(text)
            meta = data.get("metadata") if not err and isinstance(data, dict) else None
            if not isinstance(meta, dict):
                continue
            total += 1
            if meta.get("proof") in ("self-run", "external-run"):
                proven += 1
    allowed = CATALOG_BASE[0] + max(0, proven - CATALOG_BASE[1])
    if total <= allowed:
        return []
    return [
        f"catalog proof ratchet: {total} missions with {proven} proven past "
        f"doctrine-only exceeds the allowed {allowed} (base {CATALOG_BASE[0]} "
        f"missions / {CATALOG_BASE[1]} proven) — advance an existing mission's "
        "proof with a bound run report before adding breadth"
    ]


def check_evals():
    """Eval JSON files must be valid and self-consistent (ported marketingskills pattern)."""
    return _eval_validator.validate_all()


# Human-facing doc surfaces where a hardcoded catalog count would rot on every new
# mission. The count must never be spelled out here — the README badges read it
# dynamically (docs/assets/badges/, plugin.json version), and this lint fails the build
# if a number creeps back. Adding a mission must not mean rewriting counts everywhere.
COUNT_LINT_FILES = (
    "README.md", "ARCHITECTURE.md", "AGENTS.md", "docs/concepts.md",
    "docs/getting-started.md",
    ".github/CONTRIBUTING.md", ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json",
    # The GitHub About box is a repository setting, so no lint can reach it — but its
    # canonical text is a file, and that file is why the box stopped carrying a count
    # it had already gone stale on twice. Linting it keeps the count from creeping back
    # into the one surface every external indexer scrapes. See docs/about.md.
    "docs/about.md",
)
# The count-lint regex engine lives in scripts/_countlint.py (RV-D1); this module
# keeps a single re-export — the one engine name its callers read.
COUNT_LINT_RE = _countlint.COUNT_LINT_RE


def check_doc_counts():
    """Fail on a hardcoded catalog count in a human doc surface. The predecessor's own
    mission count (a historical fact about a different repo) is the one allowed exception."""
    failures = []
    for rel in COUNT_LINT_FILES:
        p = ROOT / rel
        if not p.exists():
            # The list IS the contract: a deleted surface must not silently
            # leave the lint (#563 — a gate that passes because its input
            # vanished has not run).
            failures.append(
                f"{rel}: listed in COUNT_LINT_FILES but missing — restore the "
                "surface or remove it from the list deliberately")
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            m = COUNT_LINT_RE.search(line)
            if not m and _countlint.MISSION_CONTEXT_RE.search(line):
                m = _countlint.ALL_COUNT_RE.search(line)
            if not m:
                continue
            # The predecessor's own count is history, not this catalog — but only when
            # "predecessor" precedes the matched count, so a line carrying BOTH a current
            # count and a predecessor mention is still flagged.
            if "predecessor" in line[: m.start()].lower():
                continue
            failures.append(
                f"{rel}:{i}: hardcoded catalog count '{m.group(0).strip()}' — phrase it "
                f"count-agnostically (the badges read the count dynamically)"
            )
    return failures


# #512: the Orca floor was typed by hand in three places and lagged the pin by fifteen
# releases. Any Orca version named on a line that talks about the pin or a floor must equal
# runtime/pins.json; a version named for another reason (a support-window range, an observed
# build) stays free. Distinct from check_doc_counts: this is a version, not a catalog count.
PIN_LINT_FILES = ("README.md", "docs/getting-started.md", "docs/install.md", "docs/distribution.md")
ORCA_VERSION_RE = re.compile(r"\bv?1\.4\.\d{2,3}\b")
PIN_CONTEXT_RE = re.compile(r"(?i)\bpins?\b|≥|>=|at or above")


def check_pin_version_claims():
    """Fail on a hand-typed Orca floor that disagrees with runtime/pins.json."""
    pins = ROOT / "runtime" / "pins.json"
    try:
        pin = json.loads(pins.read_text(encoding="utf-8"))["orca"]["version"].lstrip("v")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as err:
        return [f"runtime/pins.json: cannot read orca.version ({err})"]
    failures = []
    for rel in PIN_LINT_FILES:
        p = ROOT / rel
        if not p.exists():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not PIN_CONTEXT_RE.search(line):
                continue
            for m in ORCA_VERSION_RE.finditer(line):
                if m.group(0).lstrip("v") != pin:
                    failures.append(
                        f"{rel}:{i}: names Orca {m.group(0)} beside the pin, but runtime/pins.json "
                        f"pins v{pin} — update the sentence with the pin, never one without the other"
                    )
    return failures


def check_manifest_keywords():
    """Every mission dir must be a plugin.json keyword — discovery, and a guard that a new
    mission is not silently dropped from the manifest now that the description no longer lists them."""
    pj = ROOT / ".claude-plugin" / "plugin.json"
    try:
        keywords = set(json.loads(pj.read_text(encoding="utf-8")).get("keywords", []))
    except (OSError, ValueError) as err:
        return [f".claude-plugin/plugin.json: unreadable ({err})"]
    return [
        f".claude-plugin/plugin.json: mission '{d.name}' is not in keywords"
        for d in sorted(SKILLS_DIR.iterdir())
        if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").exists()
        and d.name not in keywords
    ]


CANONICAL_LEDGER_FLAGS = ("BUILD_DONE", "PR_OPEN", "BOT", "REVIEWED", "MERGED", "WT_CLEAN", "lighting")


def check_ledger_rows():
    """A mission's unit row extends the canonical schema; it may never drop a flag (#357).

    ledger-contract.md's "extend with mission fields, never drop flags" was a sentence until
    something read it: absorb-it shipped a row missing BUILD_DONE/PR_OPEN/BOT/lighting, and a
    lit/dark-eligible swap would have been invisible at RESUME. Any `| task_id |` row in a
    SKILL.md must carry every canonical flag.
    """
    failures = []
    if not SKILLS_DIR.is_dir():
        # main() exits 2 before this on the CLI path; an importer must not
        # get a silent pass for a catalog that is not there (#563).
        return [f"skills/ not found at {SKILLS_DIR} — the ledger-row check did not run"]
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith((".", "_")):
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        text, read_err = read_text_safe(skill_md)
        if read_err:
            failures.append(f"{skill_dir.name}/SKILL.md: {read_err}")
            continue
        rows = [" ".join(m.split()) for m in re.findall(r"`(\|\s*task_id\s*\|[^`]+)`", text)]
        for line in text.splitlines():
            if "`" in line:
                continue
            row = line.strip()
            if row.startswith("| task_id |"):
                rows.append(row)
        for row in rows:
            missing = [flag for flag in CANONICAL_LEDGER_FLAGS if f"| {flag} |" not in row]
            if missing:
                failures.append(
                    f"{skill_dir.name}: ledger row drops canonical flag(s) {', '.join(missing)} — "
                    "extend the canonical row, never drop flags (ledger-contract.md)")
    return failures


def check_quarantine():
    """The catalog may not route through a quarantined component (#558).

    Returns (failures, warnings). Routing violations fail: a mission composing
    a quarantined playbook, or pins.json pinning a quarantined pack ref. A
    quarantined mission still present is the designed state (preflight refuses
    its dispatch; files stay as evidence) and warns only. A missing or
    malformed deny-list fails closed in this repo.
    """
    if not (ROOT / "runtime" / "quarantine.json").is_file():
        return ["runtime/quarantine.json is missing — the deny-list is part of "
                "the catalog, not an operator extra (#558)"], []
    entries, errors, _ = _quarantine.load_quarantine(ROOT)
    if errors:
        return errors, []
    # The catalog view is quarantine_check.py's own, so this gate, `quarantine_check.py
    # --catalog` and `preflight.py --mission` read ONE composition set: clause backticks and
    # clause `name.md`, DEFERRED READS, body mentions, and every playbook those reach. This gate
    # used to build its own view from clause backticks alone, so a clause respelled
    # `build-change.md` was charged as activation load and cleared here while the CLI refused it
    # (2026-10-23 review, P1-10 / P2-11).
    try:
        view = _quarantine.catalog_view(ROOT)
    except _quarantine.QuarantineError as err:
        return [f"quarantine cannot clear the catalog: {err}"], []
    failures = _quarantine.violations(entries, {**view, "missions": set()})
    warnings = [
        f"mission {e['name']} is quarantined ({e['reason']}) but still in the "
        "catalog — dispatch is refused at preflight; files preserved as evidence"
        for e in entries if e["kind"] == "mission" and e["name"] in view["missions"]
    ]
    return failures, warnings


def check_badge_freshness(gen_module=None):
    """The generated badge JSON (docs/assets/badges/) must match current repo state, so the
    dynamically-read README badges never go stale. Regenerate with scripts/gen-badges.py.

    Every surface but one: the test count. Each PR changed it, so every PR rewrote
    docs/assets/badges/tests.json and conflicted with every other open PR. It is now the count at the
    last release (the README badge says so), regenerated by the release cut
    (`gen-badges.py --release`); here it is held to its shape only, so it can never read as a
    pass/fail claim. `gen-badges.py --check --release` is the full check the cut runs.
    `gen_module` is a test seam: an already-loaded gen-badges pointed at fixture paths."""
    if gen_module is not None:
        return gen_module.check(include_test_count=False)
    gen = ROOT / "scripts" / "gen-badges.py"
    if not gen.is_file():
        return [f"scripts/gen-badges.py missing at {gen} — the badge pipeline is gone"]
    spec = importlib.util.spec_from_file_location("_gen_badges", gen)
    if spec is None or spec.loader is None:
        return [f"scripts/gen-badges.py unloadable at {gen}"]
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check(include_test_count=False)


def check_changelog_fragments():
    """changelog.d/ fragments the release cut can fold (scripts/changelog.py). Shape only: the
    rule that CHANGELOG.md itself gains no [Unreleased] entry needs a PR base, so CI runs it as
    `changelog.py check --base`."""
    path = ROOT / "scripts" / "changelog.py"  # loaded by path, as _countlint is: no sys.path edits
    if not path.is_file():
        return ["scripts/changelog.py missing — nothing can fold changelog.d/ into a release"]
    try:
        spec = importlib.util.spec_from_file_location("_validate_changelog", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.check_fragments(ROOT / "changelog.d")
    except (OSError, ValueError) as err:  # a check reports; it never takes later gates down
        return [f"changelog fragments unreadable: {err}"]


def check_run_index():
    """One well-formed docs/runs/index/<run>.json row per dated run report (scripts/run_index.py).
    The table and its yes-count in docs/runs/README.md are generated from them at the cut."""
    path = ROOT / "scripts" / "run_index.py"  # loaded by path, as _countlint is: no sys.path edits
    if not path.is_file():
        return ["scripts/run_index.py missing — the run index has no generator"]
    try:
        spec = importlib.util.spec_from_file_location("_validate_run_index", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.check_rows(ROOT) + mod.check_snapshot(ROOT)
    except (OSError, ValueError) as err:  # a check reports; it never takes later gates down
        return [f"run index unreadable: {err}"]


def main():
    if not SKILLS_DIR.exists():
        print(f"skills/ not found at {SKILLS_DIR}", file=sys.stderr)
        return 2

    protocols = known_protocol_names()
    all_passed = True
    total = 0
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith((".", "_")):
            continue
        total += 1
        errors = validate_skill(skill_dir, protocols)
        if errors:
            all_passed = False
            print(f"FAIL {skill_dir.name}")
            for e in errors:
                print(f"   - {e}")
        else:
            print(f"ok   {skill_dir.name}")

    hidden = check_hidden_missions()
    if hidden:
        all_passed = False
        print("\nFAIL hidden missions — a SKILL.md in a `_`/`.`-prefixed skills/ directory:")
        for failure in hidden:
            print(f"   - {failure}")

    leaks = check_layer_separation()
    if leaks:
        all_passed = False
        print("\nFAIL layer separation — SKILL.md found outside skills/:")
        for leak in leaks:
            print(f"   - {leak} (only skills/<name>/ may hold a SKILL.md)")

    framed = check_lower_layer_frontmatter()
    if framed:
        all_passed = False
        print("\nFAIL layer separation — frontmatter under playbooks/ or runtime/:")
        for path in framed:
            print(f"   - {path} (frontmatter is what makes a file discoverable; "
                  "playbooks are called by name, never matched by a router)")

    doc_failures = check_protocol_doc_refs(protocols)
    if doc_failures:
        all_passed = False
        print("\nFAIL protocol cross-references — dangling refs in playbooks/runtime:")
        for failure in doc_failures:
            print(f"   - {failure}")

    identity_errors, identity_warnings = identity_collisions()
    if identity_errors:
        all_passed = False
        print("\nFAIL mission identity — two missions declare the same six points:")
        for error in identity_errors:
            print(f"   - {error}")
    for warning in identity_warnings:
        print(f"WARN mission identity — {warning}")

    ratchet_failures = check_proof_ratchet()
    if ratchet_failures:
        all_passed = False
        print("\nFAIL catalog proof ratchet — breadth has outrun proof:")
        for failure in ratchet_failures:
            print(f"   - {failure}")

    eval_errors = check_evals()
    if eval_errors:
        all_passed = False
        print("\nFAIL eval schema — invalid eval JSON or routing coverage:")
        for error in eval_errors:
            print(f"   - {error}")

    count_failures = check_doc_counts()
    if count_failures:
        all_passed = False
        print("\nFAIL count-agnostic docs — a hardcoded catalog count would rot on every new mission:")
        for failure in count_failures:
            print(f"   - {failure}")

    pin_failures = check_pin_version_claims()
    if pin_failures:
        all_passed = False
        print("\nFAIL pin-version claims — a hand-typed Orca version drifted from runtime/pins.json:")
        for failure in pin_failures:
            print(f"   - {failure}")

    budget_failures = check_load_budgets()
    if budget_failures:
        all_passed = False
        print("\nFAIL activation-load budgets — a mission outgrew, or no longer fills, its budget:")
        for failure in budget_failures:
            print(f"   - {failure}")

    keyword_failures = check_manifest_keywords()
    if keyword_failures:
        all_passed = False
        print("\nFAIL manifest keywords — a mission is missing from plugin.json keywords:")
        for failure in keyword_failures:
            print(f"   - {failure}")

    ledger_failures = check_ledger_rows()
    if ledger_failures:
        all_passed = False
        print("\nFAIL ledger rows — a mission's unit row drops canonical flags:")
        for failure in ledger_failures:
            print(f"   - {failure}")

    badge_failures = check_badge_freshness()
    if badge_failures:
        all_passed = False
        print("\nFAIL badge freshness — run scripts/gen-badges.py and commit:")
        for failure in badge_failures:
            print(f"   - {failure}")

    fragment_failures = check_changelog_fragments()
    if fragment_failures:
        all_passed = False
        print("\nFAIL changelog fragments — the release cut cannot fold changelog.d/ (see its README):")
        for failure in fragment_failures:
            print(f"   - {failure}")

    index_failures = check_run_index()
    if index_failures:
        all_passed = False
        print("\nFAIL run index — every dated run report needs one docs/runs/index/<run>.json row:")
        for failure in index_failures:
            print(f"   - {failure}")

    quarantine_failures, quarantine_warnings = check_quarantine()
    if quarantine_failures:
        all_passed = False
        print("\nFAIL quarantine — the catalog routes through a quarantined component:")
        for failure in quarantine_failures:
            print(f"   - {failure}")
    for warning in quarantine_warnings:
        print(f"WARN quarantine — {warning}")

    print()
    if all_passed:
        print(f"All {total} missions valid; three-layer separation holds; evals valid.")
        return 0
    print("Validation failed.")
    if _run_report.is_shallow(ROOT):
        # A shallow clone cannot resolve the commits run reports pin, so proven missions fail
        # here through no fault of the catalog. Fail closed, but name the fix (install.sh
        # refuses shallow clones up front with the same remedy).
        print(f"NOTE: {ROOT} is a shallow clone (git clone --depth …); run-report pins need "
              f"full history. Run `{_run_report.SHALLOW_REMEDY}` and re-run this check.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
