#!/usr/bin/env python3
"""Writer, reader and validator for the DECISIONS log.

``docs/DECISIONS.md`` was a parser without a writer: the scope-gated review
playbook reads it mechanically to decide whether a lens has earned its
auto-gate-off, but every line was hand-typed, so two coordinators could disagree
about the same log. This is the writer, and the same rules run as a check over a
file somebody else wrote.

Line format (runtime/ledger-contract.md, "DECISIONS log")::

    ts · gate-or-ask-id · class · answer · why · task_id?

``·`` (U+00B7) separates fields; the trailing ``task_id`` is optional. ``class``
is one of ``mechanical`` (one defensible answer), ``taste`` (reasonable
disagreement, reversible) or ``one-way`` (hard to reverse or out of authority).

What ``append`` refuses to write, and why each refusal exists:

* an unknown class, an empty id, an empty answer, or an empty ``why`` -- a
  decision nobody can reconstruct is not a record, and "why" is the field that
  makes the log re-readable by a fresh coordinator;
* a field containing ``·`` or a newline -- one record, one line;
* anything shaped like a credential (see ``SECRET_SHAPES``) -- the log is
  committed and permanent, so a pasted token in a "why" is permanent too. The
  refusal names the shape, never the value;
* a line whose text matches the one-way keyword net in
  ``runtime/one-way-doors.json`` but whose class is NOT ``one-way`` -- an agent
  must not be able to reclassify its own gate by choosing a milder word;
* a ``one-way`` line with no human source -- one-way doors are human-only, so
  the line must carry ``[source=human:<name>]`` as the suffix of the ``why``
  field (which keeps the format at six fields). Only the append-time
  ``--source`` flag supplies it: the same text typed into ``--why`` prose is
  refused, because a worker can type any prose. The name records who the
  coordinator states granted the door; without a pinned key it is a
  record-format check, not identity authentication. Committing the human's
  ed25519 public key as ``.orca/human-grant-pubkey`` turns authentication on:
  append then requires ``--grant-sig`` (produced by ``sign-grant`` with the
  human's seed, kept off every repo and worker via ``grant-keygen``), the
  signature binds id+answer+why+task, and ``check`` verifies every recorded
  signature (a signed line with no pinned key fails closed). Lines written
  before the pin landed carry no signature and stay readable history.

Subcommands
    append   validate and append one line
    active   list the non-superseded lines (the newest line for an id wins; an
             answer of exactly ``superseded`` retires the id entirely)
    tally    ``--lens <name>``: read ``lens-tally:<lens>`` lines newest-first and
             report the streak of consecutive zero-finding dispatches, plus
             whether that lens may auto-gate off (10+ zeros, and the lens is not
             one of the never-gate lenses)
    check    run every append-time rule over an existing file

Exit codes
    0  ok
    1  a validation failure (refused append, or ``check`` found a violation)
    2  could not run -- unreadable file, missing/invalid door registry, usage

How to wire
    The coordinator appends one line per mechanical or taste auto-resolve and one
    per human-answered one-way gate, so the log is the durable record RESUME
    re-reads before re-asking a question a previous coordinator already settled.
    The scope-gated review playbook appends ``lens-tally:<lens>`` with the
    dispatch's finding count as the answer, and calls ``tally --lens`` BEFORE
    dispatching: the gate verdict then comes from committed state that survives a
    crashed run, not from one coordinator's memory. An independent verifier runs
    ``check`` over the file: a line that trips the one-way net without the class
    and the human source fails the run, which is the machine form of "one-way is
    never auto-resolved".

    Example: ``decisions.py append --id lens-tally:security --class mechanical
    --answer 0 --why "diff touched no auth surface" --task t-14``
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CANNOT_RUN = 2

SEP = " · "
SEP_CHAR = "·"
CLASSES = ("mechanical", "taste", "one-way")
DEFAULT_LOG = "docs/DECISIONS.md"
PRIMARY_DECISIONS_ENV = "OPEN_FLEET_DECISIONS_FILE"
DECISIONS_ENV = "ORCA_DECISIONS_FILE"
DEFAULT_DOORS = Path(__file__).resolve().parent.parent / "one-way-doors.json"


def decisions_path(explicit=None):
    if explicit:
        return str(explicit)
    for var in (PRIMARY_DECISIONS_ENV, DECISIONS_ENV):
        env = (os.environ.get(var) or "").strip()
        if env:
            return env
    return DEFAULT_LOG

# Lenses whose value IS the miss they would catch: they never auto-gate off, however
# long their zero streak runs. This tuple is the EXECUTABLE form of the sentence in
# playbooks/risk-review.md; `tests/test_decisions.py` parses that sentence and requires
# the two to agree, because a policy naming three lenses and a gate enforcing two is how
# privacy silently switched itself off after ten quiet reviews (PR #277 review, P1).
NEVER_GATE = ("security", "privacy", "data-migration")
GATE_OFF_STREAK = 10

HUMAN_SOURCE_SUFFIX = re.compile(
    r"\[source=human:([^\s\]]+?)(?: sig=([0-9a-fA-F]{128}))?\]\s*$")
GRANT_PUBKEY_REL = Path(".orca") / "human-grant-pubkey"
_ED = None


def _ed25519():
    global _ED
    if _ED is None:
        here = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location("ed25519", here / "ed25519.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _ED = mod
    return _ED
HUMAN_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*$")
# A source naming an agent role is the fake-human shape itself: the marker
# exists to name the person who granted the door.
RESERVED_HUMAN_NAMES = frozenset({
    "agent", "ai", "anonymous", "auto", "automatic", "bot", "coordinator",
    "fleet", "human", "model", "nobody", "none", "orca", "system",
    "unknown", "worker",
})
TS_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}")

# Shapes, not values. A match is reported by NAME; the matched text is never echoed.
SECRET_SHAPES = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer-literal", re.compile(r"\b(Bearer|Authorization:)\s+[A-Za-z0-9._\-]{20,}")),
    ("provider-secret-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("assigned-secret", re.compile(
        r"\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[=:]\s*[\"']?[A-Za-z0-9/+._\-]{12,}")),
]


class DecisionsError(Exception):
    """Could-not-run: unreadable log, missing or invalid door registry."""


def load_doors(path=None):
    p = Path(path) if path else DEFAULT_DOORS
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise DecisionsError(f"one-way door registry {p} is unusable: {err}") from err
    doors = data.get("doors")
    if not isinstance(doors, list) or not doors:
        raise DecisionsError(f"one-way door registry {p} declares no doors")
    net = []
    for door in doors:
        did = door.get("id")
        keywords = door.get("keywords") or []
        if not did or not isinstance(keywords, list) or not keywords:
            raise DecisionsError(f"one-way door registry {p}: door {did!r} has no keyword net")
        for kw in keywords:
            net.append((did, fold(str(kw))))
    return net


# The keyword net is substring matching, so both the registered phrases and
# the probed line go through the same canonicalisation: case, hyphens and
# punctuation flatten, filler words drop ("merge it to main" is "merge to
# main"), common verb forms fold to their base ("merging"/"rotating"), and a
# small destructive-verb synonym set folds to one token ("erase the
# database" is "delete database"). A net that only catches the registered
# spelling is a rewording invitation, and rewording was the review probe.
_FILLER = frozenset({"the", "a", "an", "it", "this", "that", "these", "those",
                     "our", "your", "their", "its"})
_SYNONYMS = {"erase": "delete", "wipe": "delete", "destroy": "delete",
             "remove": "delete", "purge": "delete", "nuke": "delete",
             "launch": "deploy", "rollout": "deploy"}
_FORMS = {}
for _base, _forms in {
    "merge": ("merges", "merged", "merging"), "deploy": ("deploys", "deployed", "deploying"),
    "ship": ("ships", "shipped", "shipping"), "release": ("releases", "released", "releasing"),
    "publish": ("publishes", "published", "publishing"), "promote": ("promotes", "promoted", "promoting"),
    "delete": ("deletes", "deleted", "deleting"), "drop": ("drops", "dropped", "dropping"),
    "rotate": ("rotates", "rotated", "rotating"), "revoke": ("revokes", "revoked", "revoking"),
    "erase": ("erases", "erased", "erasing"), "remove": ("removes", "removed", "removing"),
    "freeze": ("freezes", "froze", "freezing"), "land": ("lands", "landed", "landing"),
    "charge": ("charges", "charged", "charging"), "grant": ("grants", "granted", "granting"),
    "create": ("creates", "created", "creating"), "provision": ("provisions", "provisioned", "provisioning"),
    "revert": ("reverts", "reverted", "reverting"), "restore": ("restores", "restored", "restoring"),
}.items():
    for _form in _forms:
        _FORMS[_form] = _base


def _canon(token):
    token = _FORMS.get(token, token)
    token = _SYNONYMS.get(token, token)
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        token = token[:-1]
    return token


def fold(text):
    tokens = re.findall(r"[a-z0-9]+", text.lower().replace("-", " ").replace("_", " "))
    return " ".join(_canon(t) for t in tokens if t not in _FILLER)


def human_grant_of(record):
    """(name, sig-hex-or-None, why-core) from the canonical why suffix, or
    (None, None, why). Only the suffix counts, the name must be
    person-shaped, and an agent role name is refused by shape."""
    why = record.get("why", "")
    match = HUMAN_SOURCE_SUFFIX.search(why)
    if not match:
        return None, None, why
    name, sig = match.group(1), match.group(2)
    if not HUMAN_NAME.match(name) or name.lower() in RESERVED_HUMAN_NAMES:
        return None, None, why
    return name, sig.lower() if sig else None, why[:match.start()].rstrip()


def human_source_of(record):
    """The recorded human name, or None (see human_grant_of)."""
    return human_grant_of(record)[0]


def grant_payload(ident, answer, why_core, task_id=""):
    """Canonical bytes a human grant signature binds (domain-separated)."""
    return ("orca-fleet human grant v1\n" + "\n".join(
        [ident, answer, why_core, task_id or ""])).encode("utf-8")


def grant_pubkey(log_path):
    """Pinned human-grant pubkey bytes for this log, or None when unpinned.

    Only the owning repository ROOT's pin counts (the first ancestor of the
    log carrying `.git`, else this script's own repo). A key dropped beside
    the log by a worker must never outrank the committed root pin — the
    ancestor search this replaced let `docs/.orca/…` override the human's
    key (PR #546 review). A malformed pin is could-not-run, never a pass."""
    resolved = Path(log_path).resolve()
    root = Path(__file__).resolve().parent.parent.parent
    for parent in resolved.parents:
        if (parent / ".git").exists():
            root = parent
            break
    for pin in [root / GRANT_PUBKEY_REL]:
        try:
            if not pin.exists():
                continue
            text = pin.read_text(encoding="utf-8").strip()
        except OSError as err:
            raise DecisionsError(f"{pin} is unreadable: {err}") from err
        try:
            pub = bytes.fromhex(text)
        except ValueError as err:
            raise DecisionsError(f"{pin} is not a hex public key: {err}") from err
        if len(pub) != 32:
            raise DecisionsError(f"{pin} is not a 32-byte public key")
        return pub
    return None


def door_hits(text, net):
    probe = fold(text)
    return sorted({door_id for door_id, kw in net if kw in probe})


def secret_hits(text):
    return sorted({name for name, pattern in SECRET_SHAPES if pattern.search(text)})


def format_line(ts, ident, klass, answer, why, task_id=None):
    fields = [ts, ident, klass, answer, why]
    if task_id:
        fields.append(task_id)
    return SEP.join(fields)


def parse_line(line):
    """Return a dict for a DECISIONS record line, or None when the line is prose.

    A record is identified by its FIRST field being an ISO date. Without that
    test the file's own format legend (``ts · gate-or-ask-id · class · …``)
    parses as a record and fails its own check.
    """
    if SEP_CHAR not in line:
        return None
    parts = [p.strip() for p in line.strip().lstrip("-*# ").split(SEP_CHAR)]
    if len(parts) < 5:
        return None
    if not TS_PREFIX.match(parts[0].strip("`")):
        return None
    parts[0] = parts[0].strip("`")
    record = {
        "ts": parts[0], "id": parts[1], "class": parts[2],
        "answer": parts[3], "why": SEP_CHAR.join(parts[4:5]),
        "task_id": parts[5] if len(parts) > 5 else "",
        "raw": line.rstrip("\n"),
    }
    if len(parts) > 6:
        record["why"] = SEP_CHAR.join(parts[4:-1])
        record["task_id"] = parts[-1]
    return record


def validate(record, net, grant_pub=None):
    """Return a list of violation strings for one parsed record."""
    problems = []
    if not record["id"]:
        problems.append("empty gate-or-ask id")
    if record["class"] not in CLASSES:
        problems.append(f"class {record['class']!r} is not one of {', '.join(CLASSES)}")
    if not record["answer"]:
        problems.append("empty answer")
    if not record["why"]:
        problems.append("empty why (a decision nobody can reconstruct is not a record)")
    shapes = secret_hits(record["raw"])
    if shapes:
        problems.append(f"credential-shaped text ({', '.join(shapes)}) — the log is permanent")
    suffix_match = HUMAN_SOURCE_SUFFIX.search(record.get("why", ""))
    if record["class"] != "one-way" and suffix_match and suffix_match.group(2):
        problems.append("grant signature on a non-one-way line — a signed suffix "
                        "only ever binds a one-way grant; refusing an unchecked "
                        "signed-looking marker")
    hits = door_hits(record["raw"], net)
    if hits and record["class"] != "one-way":
        problems.append(
            f"matches the one-way net ({', '.join(hits)}) but is classed {record['class']!r} — "
            "one-way doors are human-only and are never auto-resolved"
        )
    if record["class"] == "one-way":
        name, sig, why_core = human_grant_of(record)
        if name is None:
            problems.append("class one-way with no human source — the why must end with "
                            "[source=human:<name>] recorded via append --source")
        elif sig is not None:
            if grant_pub is None:
                problems.append(
                    "carries a grant signature but no human grant pubkey is pinned "
                    "(.orca/human-grant-pubkey) — a signature nothing can verify fails closed")
            else:
                try:
                    verified = _ed25519().checkvalid(
                        bytes.fromhex(sig),
                        grant_payload(record["id"], record["answer"], why_core,
                                      record.get("task_id", "")),
                        grant_pub)
                except Exception:
                    verified = False
                if not verified:
                    problems.append(
                        "grant signature does not verify against the pinned human "
                        "grant pubkey for this line's id/answer/why/task")
    return problems


def read_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as err:
        raise DecisionsError(f"{path} is unreadable: {err}") from err
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        record = parse_line(line)
        if record:
            record["lineno"] = i
            out.append(record)
    return out


_UNDATED = datetime.min.replace(tzinfo=timezone.utc)


def _instant(ts):
    """The UTC instant a DECISIONS timestamp names, for ordering.

    Not the raw string. TS_PREFIX accepts anything beginning with a date, so a record may carry an
    offset — and offsets do not sort lexicographically: `2026-09-11T01:00:00+05:00` IS
    `2026-09-10T20:00:00Z`, earlier than `2026-09-11T00:00:00Z`, and sorted as text it came out
    later and won (PR #308 review, P1). A naive stamp is read as UTC, which is what the format
    legend asks for and the only sensible reading of a bare local time. An unparseable stamp sorts
    before everything, so a line whose time cannot be read never displaces one whose time can."""
    text = (ts or "").strip().strip("`")
    # The format's own stamps end in `Z`, but fromisoformat learned to read that
    # suffix only in 3.11 — on older interpreters every record sorted _UNDATED,
    # ordering silently fell back to file position, and only this fix's own
    # tests noticed (#320).
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return _UNDATED
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def recency(record, position):
    """Sort key for "which of these lines is newest": instant first, file order to break ties.

    Public because floor_guard.py orders waiver records by it: a waiver is a DECISIONS record, and
    two modules deciding "newest" differently is how a retired waiver keeps granting (PR #308
    review, P1).

    Position alone was the whole ordering guarantee (#318), which made the ledger's answer depend
    on who appended last rather than on when the decision was taken — so any merge, reorder or
    out-of-order append silently changed which decision was live. Position stays as the tiebreak
    because two decisions really can share an instant, and there the old behaviour is the only
    information available."""
    return (_instant(record.get("ts", "")), position)


def active(records):
    """Newest line per id wins — newest by TIMESTAMP, file order breaking ties. An answer of
    exactly 'superseded' retires the id."""
    latest = {}
    for position, record in enumerate(records):
        key = recency(record, position)
        current = latest.get(record["id"])
        if current is None or key > current[0]:
            latest[record["id"]] = (key, record)
    return [r for _key, r in latest.values() if r["answer"].strip().lower() != "superseded"]


def tally(records, lens):
    """Consecutive zero-finding dispatches for a lens, newest-first.

    Ordered by the same key as active() (#318): a streak counted in file order would be a
    different streak after a merge."""
    ident = f"lens-tally:{lens}"
    rows = [r for _key, r in sorted(
        ((recency(r, i), r) for i, r in enumerate(records) if r["id"] == ident),
        key=lambda pair: pair[0])]
    streak = 0
    for record in reversed(rows):
        if re.fullmatch(r"0+", record["answer"].strip()):
            streak += 1
        else:
            break
    never = lens in NEVER_GATE
    return {
        "lens": lens,
        "dispatches": len(rows),
        "zero_streak": streak,
        "never_gate": never,
        "may_gate_off": (not never) and streak >= GATE_OFF_STREAK,
    }


def cmd_append(args, net):
    pub = grant_pubkey(args.file)
    ts = args.ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    why = args.why
    if args.grant_sig and args.klass != "one-way":
        print("decisions: --grant-sig binds a one-way human grant; it has no meaning "
              f"on a {args.klass} line", file=sys.stderr)
        return EXIT_VIOLATION
    if args.klass == "one-way" and not args.source:
        print("decisions: class one-way with no human source — requires --source human:<name>, passed by the "
              "coordinator who received the grant — a source marker typed into --why "
              "is prose any worker can write, not a source", file=sys.stderr)
        return EXIT_VIOLATION
    if args.grant_sig and pub is None:
        print("decisions: --grant-sig given but no human grant pubkey is pinned "
              "(.orca/human-grant-pubkey) — refusing a signature nothing can verify",
              file=sys.stderr)
        return EXIT_VIOLATION
    if args.source:
        match = re.fullmatch(r"human:(\S+)", args.source)
        name = match.group(1) if match else ""
        if not HUMAN_NAME.match(name) or name.lower() in RESERVED_HUMAN_NAMES:
            print("decisions: --source must be shaped human:<name> and name a person, "
                  "not an agent role", file=sys.stderr)
            return EXIT_VIOLATION
        embedded = HUMAN_SOURCE_SUFFIX.search(why)
        effective_sig = args.grant_sig
        if embedded:
            if embedded.group(1) != name or (
                    embedded.group(2) and effective_sig
                    and embedded.group(2).lower() != effective_sig.lower()):
                print("decisions: --why carries a source marker that does not match "
                      "--source; refusing a smuggled or mismatched source", file=sys.stderr)
                return EXIT_VIOLATION
            effective_sig = effective_sig or embedded.group(2)
            why = why[:embedded.start()].rstrip()
        elif "source=" in why:
            print("decisions: --why carries a source marker that does not match "
                  "--source; refusing a smuggled or mismatched source", file=sys.stderr)
            return EXIT_VIOLATION
        if effective_sig and args.klass != "one-way":
            print("decisions: a grant signature embedded in --why binds a one-way "
                  f"grant; it has no meaning on a {args.klass} line", file=sys.stderr)
            return EXIT_VIOLATION
        if args.klass == "one-way" and pub is not None and not effective_sig:
            print("decisions: a human grant pubkey is pinned, so a one-way append "
                  "requires --grant-sig from the human's key (`sign-grant`)",
                  file=sys.stderr)
            return EXIT_VIOLATION
        if effective_sig:
            if not re.fullmatch(r"[0-9a-fA-F]{128}", effective_sig):
                print("decisions: --grant-sig must be 128 hex characters", file=sys.stderr)
                return EXIT_VIOLATION
            why = f"{why} [source={args.source} sig={effective_sig.lower()}]"
        else:
            why = f"{why} [source={args.source}]"
    for name, value in (("id", args.id), ("answer", args.answer), ("why", why),
                        ("task", args.task or "")):
        if SEP_CHAR in value or "\n" in value:
            print(f"decisions: {name} may not contain '{SEP_CHAR}' or a newline "
                  "(one record, one line)", file=sys.stderr)
            return EXIT_VIOLATION
    line = format_line(ts, args.id.strip(), args.klass, args.answer.strip(), why.strip(),
                       (args.task or "").strip())
    record = parse_line(line)
    if record is None:
        print("decisions: refusing to write an unparseable line", file=sys.stderr)
        return EXIT_VIOLATION
    record["lineno"] = 0
    problems = validate(record, net, pub)
    if problems:
        print("decisions: refused:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return EXIT_VIOLATION
    path = Path(args.file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        exists = path.exists()
        with path.open("a", encoding="utf-8") as fh:
            if not exists:
                fh.write("# DECISIONS\n\n"
                         "`ts · gate-or-ask-id · class · answer · why · task_id?`\n\n")
            fh.write(line + "\n")
    except OSError as err:
        raise DecisionsError(f"{path} could not be appended: {err}") from err
    print(line)
    return EXIT_OK


def cmd_active(args, _net):
    records = read_lines(args.file)
    rows = active(records)
    if args.json:
        print(json.dumps([{k: r[k] for k in ("ts", "id", "class", "answer", "why", "task_id")}
                          for r in rows], indent=2))
    else:
        for r in rows:
            print(r["raw"])
    return EXIT_OK


def cmd_tally(args, _net):
    records = read_lines(args.file)
    result = tally(records, args.lens)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        gate = "may auto-gate off" if result["may_gate_off"] else (
            "NEVER_GATE" if result["never_gate"] else "stays on")
        print(f"lens={result['lens']} dispatches={result['dispatches']} "
              f"zero_streak={result['zero_streak']} → {gate}")
    return EXIT_OK


def cmd_check(args, net):
    pub = grant_pubkey(args.file)
    records = read_lines(args.file)
    failures = []
    for record in records:
        for problem in validate(record, net, pub):
            failures.append(f"{args.file}:{record['lineno']}: {problem}")
    if failures:
        for f in failures:
            print(f, file=sys.stderr)
        return EXIT_VIOLATION
    print(f"decisions: {len(records)} record(s) valid in {args.file}")
    return EXIT_OK


def _seed_in_unignored_worktree(path):
    """True when `path` sits in ANY git work tree without ignore coverage.

    Delegates to dispatch-sign.py's custody probe (the fleet's single
    implementation: a .git-ancestor walk plus an env-aware rev-parse, then
    check-ignore, failing closed on unknown ignore status) so the two seed
    tools can never drift apart (PR #546 review)."""
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        "dispatch_sign", here / "dispatch-sign.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._in_unignored_worktree(path)


def cmd_grant_keygen(args, _net):
    """Generate the human grant seed OFF-repo and its public key beside it."""
    out = Path(args.out).expanduser()
    pub_path = Path(str(out) + ".pub")
    if _seed_in_unignored_worktree(out) and not args.in_repo_ok:
        print("decisions: grant-keygen refuses to write a human seed inside a git "
              "work tree that does not ignore it (it is a private key — one "
              "`git add -A` would publish it; keep it with your other keys, e.g. "
              "~/.orca-fleet/human-grant-key; --in-repo-ok overrides)", file=sys.stderr)
        return EXIT_VIOLATION
    if out.exists() or pub_path.exists():
        print(f"decisions: refusing to overwrite {out} or {pub_path}", file=sys.stderr)
        return EXIT_VIOLATION
    seed = os.urandom(32)
    pub = _ed25519().publickey(seed)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(seed.hex() + "\n")
        pub_path.write_text(pub.hex() + "\n", encoding="utf-8")
    except OSError as err:
        raise DecisionsError(f"grant key could not be written: {err}") from err
    print(pub.hex())
    print(f"decisions: seed at {out} (never commit it, never give it to a worker); "
          f"commit {pub_path} as .orca/human-grant-pubkey to turn signed grants on",
          file=sys.stderr)
    return EXIT_OK


def cmd_sign_grant(args, _net):
    """Print the grant signature (hex only) for one exact decision line."""
    try:
        seed = bytes.fromhex(Path(args.key).expanduser().read_text(
            encoding="utf-8").strip())
    except (OSError, ValueError) as err:
        raise DecisionsError(f"grant key {args.key} is not a readable hex seed: {err}") from err
    if len(seed) != 32:
        raise DecisionsError(f"grant key {args.key} is not a 32-byte seed")
    why = args.why
    embedded = HUMAN_SOURCE_SUFFIX.search(why)
    if embedded:
        why = why[:embedded.start()].rstrip()
    ed = _ed25519()
    sig = ed.signature(
        grant_payload(args.id.strip(), args.answer.strip(), why.strip(),
                      (args.task or "").strip()),
        seed, ed.publickey(seed))
    print(sig.hex())
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(
        prog="decisions.py",
        description="Append to, read and validate the DECISIONS log.",
        epilog="exit 0 ok / 1 validation failure / 2 could-not-run",
    )
    p.add_argument("--file", default=decisions_path(),
                   help=f"DECISIONS log path (default ${PRIMARY_DECISIONS_ENV}, ${DECISIONS_ENV}, or {DEFAULT_LOG})")
    p.add_argument("--doors", default=None, help="one-way door registry (default runtime/one-way-doors.json)")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("append", help="validate and append one decision line")
    a.add_argument("--id", required=True, help="gate or ask id, e.g. lens-tally:security")
    a.add_argument("--class", dest="klass", required=True, choices=CLASSES, help="decision class")
    a.add_argument("--answer", required=True, help="what was decided (a finding count, for a lens tally)")
    a.add_argument("--why", required=True, help="why — never empty")
    a.add_argument("--task", default=None, help="optional task id")
    a.add_argument("--source", default=None, help="human:<name> — required for class one-way")
    a.add_argument("--grant-sig", default=None,
                   help="128-hex grant signature from sign-grant; required for one-way "
                        "once .orca/human-grant-pubkey is pinned")
    a.add_argument("--ts", default=None, help="ISO timestamp (default: now, UTC)")

    sub.add_parser("active", help="list non-superseded decisions").add_argument(
        "--json", action="store_true", help="emit JSON")

    t = sub.add_parser("tally", help="zero-finding dispatch streak for a lens")
    t.add_argument("--lens", required=True, help="lens name, e.g. security")
    t.add_argument("--json", action="store_true", help="emit JSON")

    sub.add_parser("check", help="validate an existing log")

    k = sub.add_parser("grant-keygen", help="generate the human grant keypair (seed off-repo)")
    k.add_argument("--out", required=True, help="seed path, e.g. ~/.orca-fleet/human-grant-key")
    k.add_argument("--in-repo-ok", action="store_true",
                   help="allow writing the seed inside this repo (not recommended)")

    s = sub.add_parser("sign-grant", help="print the grant signature for one decision line")
    s.add_argument("--key", required=True, help="human grant seed path from grant-keygen")
    s.add_argument("--id", required=True)
    s.add_argument("--answer", required=True)
    s.add_argument("--why", required=True)
    s.add_argument("--task", default=None)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"append": cmd_append, "active": cmd_active, "tally": cmd_tally,
                "check": cmd_check, "grant-keygen": cmd_grant_keygen,
                "sign-grant": cmd_sign_grant}
    try:
        net = load_doors(args.doors)
        return handlers[args.command](args, net)
    except DecisionsError as err:
        print(f"decisions: could not run: {err}", file=sys.stderr)
        return EXIT_CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main())
