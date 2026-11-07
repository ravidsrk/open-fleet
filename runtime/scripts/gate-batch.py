#!/usr/bin/env python3
"""gate-batch.py — run-close human gates as data, not prose (#419).

The 2026-09-14 run parked maintainer questions in a hand-edited gate-batch.md:
no schema, no state machine, no reminder when a gate sat owed for days. This
tool keeps the same gate semantics (owed/answered/waived/overtaken) but stores
each gate as a typed record in docs/runs/<run>/gate-batch.json. The .md stays
beside it as a rendered VIEW: every mutation re-renders it on save
(`render --check` verifies the two agree), so prose never drifts from the
store. `related`/`blocking` are store-only and never render.

State machine: add creates owed; answer/waive/overtake move owed -> their
status exactly once (re-transitioning is an error, not an overwrite — the
record is history). stale REPORTS gates owed >= N days; it never notifies
anyone (auto-escalation is out of scope). list WARNS (stderr, exit 0) when a
unit manifest cites a gate id the batch does not carry.

Storage: one JSON file per run, docs/runs/<run>/gate-batch.json. Pass --run
<dir> or an explicit --file (tests and scratch batches use --file).

NOT upstream decision-gates: this tool never touches `orca orchestration
gate-create` / `gate-resolve` / `gate-list`. Those block a task inside the
runtime; these gates are LOCAL run-close records — owed questions a run parks
for its maintainer, answered by hand. Same word, two mechanisms; this file is
the local one.
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
import datetime
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path

SCHEMA_TAG = "gate-batch/1"
STATUSES = ("owed", "answered", "waived", "overtaken")
# Who answered or waived, as decisions.py records a human grant: `human:<name>`. An answer with no
# recorded human is prose anyone could have typed (2026-10-26 review); records written before the
# field existed carry none and stay valid history.
HUMAN_SOURCE = re.compile(r"^human:\S+$")
TERMINAL = ("answered", "waived", "overtaken")
GATE_ID_RE = re.compile(r"^G[0-9]+$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
# A parked unit cites a gate as "gate-batch.json G<n>" (pre-tooling refs say
# gate-batch.md; both resolve). The id must sit right at the anchor — bare "G3"
# prose elsewhere ("the G3 ASK body") is not a citation. Covered forms:
# "gate-batch.md G3", "gate-batch.md:22 (G2 ...)" (line-anchored), "G1-G4"
# (a range counts every id inside it, not just its endpoints).
CITE_RE = re.compile(r"gate-batch\.(?:md|json)(?::[0-9]+)?\s*\(?\s*"
                     r"(G[0-9]+(?:\s*-\s*G[0-9]+)?)")
CITE_ID_RE = re.compile(r"\bG[0-9]+\b")
CITE_RANGE_RE = re.compile(r"^(G[0-9]+)\s*-\s*(G[0-9]+)$")
REQUIRED_BATCH_KEYS = ("schema", "run_id", "run_title", "intro", "gates",
                       "resolved_by_events")
REQUIRED_GATE_KEYS = ("id", "title", "question", "asked", "status", "answer",
                      "answered", "related", "blocking")
# Keys a gate MAY carry: `source` (human:<name>) arrived 2026-10-26; earlier records lack it.
# `grant_sig` (W3-06): the human's Ed25519 signature over the terminal record (answer_payload).
OPTIONAL_GATE_KEYS = ("source", "grant_sig")
GRANT_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
# A caller that sets one of these claims a sound (off-worker) lane, as for verify-gate.sh.
PROVENANCE_VARS = ("OPEN_FLEET_PROVENANCE", "ORCA_PROVENANCE")
ANSWER_DOMAIN = "open-fleet gate-batch answer v1\n"
# What makes a gate the gate the anchor asked (PR #719 review round 3): the fields a human reads
# before answering. `blocking` is held separately: a gate blocks every ref either record names.
IDENTITY_FIELDS = ("title", "question", "asked")


class GateError(Exception):
    """A usage or store error: the CLI prints it and exits 2."""


# --- W3-06: who closed a gate --------------------------------------------------------------
# The store is a plain JSON file and `source` is only shape-checked, so `"status": "answered",
# "source": "human:<anyone>"` is a record any worker can type — and the run-close predicate
# (`list --status owed --blocking <unit>`, the release gate's own check) read such a gate as
# answered by a human (2026-10-27 security audit, W3-06). Once the human grant key decisions.py
# reads is pinned (.orca/human-grant-pubkey), a terminal gate counts only with a signature that
# verifies over the run, the gate, its status, text, date and source; one that does not is OWED.
# On a lane claiming soundness, no pinned key means no answer verifies. No key and no sound lane:
# the behaviour before W3-06, unchanged.

def _decisions():
    """decisions.py, loaded by path: it owns the human grant key (where the pin is read, the
    --pin-ref anchor, the sound-lane rule) and the Ed25519 module it verifies with. None when
    it is not beside this script."""
    path = Path(__file__).resolve().parent / "decisions.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("decisions_for_gate_batch", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sound_lane():
    """`VAR=value` for the first provenance variable set, or None (the advisory lane)."""
    return next((f"{var}={os.environ[var]}" for var in PROVENANCE_VARS
                 if (os.environ.get(var) or "").strip()), None)


def trust_key(batch_path, pin_ref=None):
    """The pinned human grant key for this batch's repository (32 bytes), or None — read as
    decisions.py reads it (the repository root's pin, or the pin at --pin-ref). On a lane claiming
    soundness --pin-ref is required: without it the key would come from the working tree the
    checked change writes, where a swapped or DELETED pin turns every typed answer back on."""
    lane = sound_lane()
    if lane and not pin_ref:
        raise GateError(f"{lane} claims a sound lane, but no --pin-ref names where the human "
                        "grant key is read; the working tree's pin is the checked change's to "
                        "swap or delete (W3-06)")
    dec = _decisions()
    if dec is None:
        root = batch_repo(batch_path)
        if pin_ref or sound_lane() or (root / ".orca" / "human-grant-pubkey").exists():
            raise GateError("decisions.py, which reads and verifies the human grant key, is not "
                            "beside this script — a human answer cannot be told from a typed "
                            "one; fail-closed (W3-06)")
        return None
    try:
        return dec.grant_pubkey(batch_path, pin_ref)
    except dec.DecisionsError as err:
        raise GateError(str(err)) from err


def answer_payload(data, gate):
    """The bytes a human signs to close `gate`: domain tag + one JSON array of every field that
    says what was decided, by whom, when, in which run — so the signature moves with nothing."""
    fields = [data["run_id"], gate["id"], gate["title"], gate["question"], gate["asked"],
              gate["status"], gate["answer"], gate["answered"], gate.get("source")]
    return (ANSWER_DOMAIN + json.dumps(fields, ensure_ascii=False,
                                       separators=(",", ":"))).encode("utf-8")


def answer_verified(data, gate, pub):
    """True when `gate` carries a grant_sig that verifies under `pub` over answer_payload."""
    sig = gate.get("grant_sig")
    dec = _decisions() if pub is not None else None
    if dec is None or not (isinstance(sig, str) and GRANT_SIG_RE.match(sig)):
        return False
    try:
        return bool(dec._ed25519().checkvalid(bytes.fromhex(sig), answer_payload(data, gate), pub))
    except Exception:  # a malformed signature verifies nothing
        return False


def effective_status(data, gate, pub=None, sound=False):
    """The status the close predicate reads: a terminal gate the trust rule cannot verify is
    OWED. With no key and no sound lane, the recorded status stands."""
    if gate["status"] == "owed" or (pub is None and not sound):
        return gate["status"]
    return gate["status"] if answer_verified(data, gate, pub) else "owed"


# --- PR #719 review round 3: WHICH gates are owed --------------------------------------------
# A signature authenticates each answer; nothing authenticated the SET. With the key pinned at
# refs/remotes/origin/main, a worker wrote `"gates": []`, re-rendered the view, and `list --status
# owed` owed nothing, so release gate 1 passed. The set is now read where the key is read:
# --pin-ref is resolved ONCE to a commit, the key AND the batch at this batch's path are both read
# at that commit, and every gate the anchor's batch carries must be here with the same title,
# question and asked date. One missing (deleted, renamed) or altered is OWED, listed from the
# anchor's record on stdout, where the close predicate looks, and a gate blocks every ref either
# record names (dropping one hides nothing); a batch claiming another run owes every anchored
# gate; a duplicate id is a store error. What the anchor never carried — a gate added and dropped
# on one branch — it cannot hold.

def _gitexec():
    """gitexec.py, by path: the hardened git the anchor is read with and the one exact-name rule
    it is resolved under. Missing beside this script is could-not-run."""
    path = Path(__file__).resolve().parent / "gitexec.py"
    if not path.is_file():
        raise GateError("gitexec.py, the hardened git the anchor is read with, is not beside "
                        "this script; fail-closed")
    spec = importlib.util.spec_from_file_location("gitexec_for_gate_batch", path)
    gitexec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gitexec)
    return gitexec


def _git(root, *args):
    """git through gitexec.py's hardened executor (no repo config, hooks or replace refs), as
    decisions.py reads the key."""
    gitexec = _gitexec()
    try:
        return subprocess.run(gitexec.argv("-C", str(root), *args), capture_output=True,
                              timeout=60, env=gitexec.env(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as err:
        raise GateError(f"git {args[0]} failed to run: {err}") from err


def _read_gitfile_text(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, 4096).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def _linked_worktree_of(inner, outer):
    """True when `inner` is a genuine `git worktree add` linked worktree of `outer` (W5-03, C20)."""
    gitfile, admin = inner / ".git", outer / ".git" / "worktrees"
    if (outer / ".git").is_symlink():
        return False
    text = _read_gitfile_text(gitfile)
    if not text or not text.startswith("gitdir:"):
        return False
    target = Path(text[len("gitdir:"):].strip())
    target = Path(os.path.realpath(target if target.is_absolute() else inner / target))
    if target.parent != Path(os.path.realpath(admin)) or not target.is_dir():
        return False
    back = _read_gitfile_text(target / "gitdir")
    if not back:
        return False
    back_path = Path(back) if Path(back).is_absolute() else target / back
    return os.path.realpath(back_path) == os.path.realpath(gitfile)


def batch_repo(batch_path):
    """The repository a batch belongs to, found as decisions.py finds the key's: the enclosing
    repository of the path, refusing nested submodules or planted `.git` directories that are not
    genuine linked worktrees of their enclosing repository (C20)."""
    lexical = Path(os.path.abspath(batch_path))
    real = lexical.resolve()
    found = []
    for candidate in (*real.parents, *lexical.parents):
        if os.path.lexists(candidate / ".git"):
            rp = Path(os.path.realpath(candidate))
            if rp not in found:
                found.append(rp)
    if not found:
        return repo_root()
    if len(found) == 1:
        return found[0]
    if len(found) == 2 and _linked_worktree_of(found[0], found[1]):
        return found[0]
    raise GateError(
        f"the nearest repository root {found[0]} is nested inside the repository {found[-1]} "
        "(a submodule, vendored repository or planted .git): refusing to resolve the governance "
        "anchor in a nested repository (C20)"
    )


def anchor_commit(root, pin_ref):
    """--pin-ref resolved ONCE to a commit id, under the rule decisions.py, verify.py and
    run_report.py answer to (gitexec.remote_tracking_commit, W3-07): a commit id that names that
    commit object, or a full refs/remotes/… ref that EXISTS under exactly that name, every
    symbolic hop remote-tracking too. A local branch, tag, HEAD or short name is the checked
    change's to move — and so is refs/heads/refs/remotes/…, which `rev-parse refs/remotes/…`
    reaches by ref-name expansion when the remote-tracking ref is absent, and a revision suffix
    (~1, @{1}) names an older commit than the ref. The anchor is the only thing that tells a
    deleted gate from one never asked."""
    if not pin_ref or pin_ref.startswith("-"):
        raise GateError(f"--pin-ref {pin_ref!r} must name a commit or a ref, not an option")

    def run(*args):
        proc = _git(root, *args)  # surrogateescape: two non-UTF-8 refnames never decode alike
        return proc.returncode, proc.stdout.decode("utf-8", "surrogateescape")

    commit, _target, why = _gitexec().remote_tracking_commit(run, pin_ref)
    if commit is None:
        raise GateError(f"--pin-ref {pin_ref!r} {why} — no anchor commit in {root} (W3-07)")
    return commit


def anchored_rel(batch_path, root):
    """The batch's path inside `root`, as git names it. A symlink inside the repository that
    redirects the read (docs/runs/<run> -> another run's directory) is refused: the store read
    must be the one at the path the anchor is consulted for."""
    lexical = Path(os.path.abspath(batch_path))
    real = lexical.resolve()
    try:
        rel = real.relative_to(root)
    except ValueError:
        raise GateError(f"{batch_path} is not inside {root}, the repository whose commit "
                        "anchors it (--pin-ref)") from None
    n = len(rel.parts)
    if lexical.parts[-n:] != rel.parts or Path(*lexical.parts[:-n]).resolve() != root:
        raise GateError(f"{batch_path} reaches {rel.as_posix()} through a symlink inside the "
                        "repository: the store read would not be the one the anchor names; "
                        "fail-closed")
    return rel.as_posix()


def anchored_batch(batch_path, root, commit):
    """The batch at `commit` for this batch's path, validated — or None when that commit carries
    none there (a run newer than the anchor). Listed but unreadable or invalid is could-not-run."""
    rel = anchored_rel(batch_path, root)
    at = f"{rel} at {commit[:12]}"
    listing = _git(root, "ls-tree", "-z", "--full-tree", commit, "--", rel)
    if listing.returncode != 0:
        raise GateError(f"cannot list {at}")
    entries = [e for e in listing.stdout.decode("utf-8", "replace").split("\0") if e]
    entry = next((e for e in entries if e.split("\t", 1)[-1] == rel), None)
    if entry is None:
        return None
    mode, kind, obj = entry.split("\t", 1)[0].split()
    if kind != "blob" or mode not in ("100644", "100755"):
        raise GateError(f"{at} is not a regular file ({mode} {kind}); fail-closed")
    blob = _git(root, "cat-file", "blob", obj)
    if blob.returncode != 0:
        raise GateError(f"{at} is listed but its blob is unreadable here; fail-closed")
    try:
        data = json.loads(blob.stdout.decode("utf-8"))
        validate_batch(data)
    except (UnicodeDecodeError, json.JSONDecodeError, GateError) as err:
        raise GateError(f"the batch {at} is not a valid store ({err}); fail-closed") from None
    return data


def read_trust(batch_path, pin_ref=None):
    """(key, anchored batch, anchor commit) for a read of the close predicate. With --pin-ref it
    is ONE commit: the key and the batch are both read at it. Without, (key, None, None)."""
    if not pin_ref:
        return trust_key(batch_path), None, None
    root = batch_repo(batch_path)
    commit = anchor_commit(root, pin_ref)
    return trust_key(batch_path, commit), anchored_batch(batch_path, root, commit), commit


def anchor_drift(data, anchored, commit):
    """{gate id: why it is owed} for every gate the anchored batch carries that this batch lacks
    or has altered. No anchored batch, no drift."""
    if not anchored:
        return {}
    at = f"the batch at {commit[:12]}"
    if data["run_id"] != anchored["run_id"]:
        return {g["id"]: f"this batch claims run {data['run_id']!r}; {at} is run "
                         f"{anchored['run_id']!r}" for g in anchored["gates"]}
    here = {g["id"]: g for g in data["gates"]}
    drift = {}
    for gate in anchored["gates"]:
        mine = here.get(gate["id"])
        if mine is None:
            drift[gate["id"]] = f"in {at}, missing here: deleted or renamed"
            continue
        changed = [k for k in IDENTITY_FIELDS if mine[k] != gate[k]]
        if changed:
            drift[gate["id"]] = f"its {'/'.join(changed)} differ from {at}"
    return drift


def _merged_refs(*records):
    """Each ref list (`blocking`, `related`) as the union of `records`, first record's order."""
    merged = {}
    for key in ("blocking", "related"):
        merged[key] = []
        for record in records:
            merged[key] += [r for r in record[key] if r not in merged[key]]
    return merged


def close_view(data, pub=None, sound=False, anchored=None, commit=None):
    """[(gate, effective status, blocked refs, note)] — every gate the close predicate and the
    views (list, stale, show) read: this batch's, then each anchored gate it lacks. A gate that
    drifted from the anchor (missing, re-worded, re-dated, another run) is owed and is shown FROM
    THE ANCHOR'S RECORD — its title, question, asked date and recorded answer — so a moved date
    cannot drop it out of `stale` and a substituted question is never what `show` prints (PR
    #719 review round 4). Every gate carries the union of both records' blocking and related
    refs; `note` says why a gate drifted (None when it agrees)."""
    drift = anchor_drift(data, anchored, commit)
    theirs = {g["id"]: g for g in (anchored or {}).get("gates", [])}
    view = []
    for gate in data["gates"]:
        anchor = theirs.get(gate["id"])
        note = drift.get(gate["id"])
        shown = "owed" if note else effective_status(data, gate, pub, sound)
        record = dict(anchor if note else gate)
        if anchor is not None:
            record.update(_merged_refs(record, gate if note else anchor))
        view.append((record, shown, record["blocking"], note))
    here = {g["id"] for g in data["gates"]}
    view += [(dict(g), "owed", list(g["blocking"]), drift[g["id"]]) for g in theirs.values()
             if g["id"] not in here]
    return view


def note_anchor(pub, pin_ref, anchored, commit):
    """Say on stderr when the gate set is not held to an anchor (exit status unchanged)."""
    if pin_ref and anchored is None:
        print(f"gate-batch.py: NOTE — {commit[:12]} carries no batch at this path, so no "
              "anchored gate set holds this one (a run newer than the anchor): each gate is "
              "judged by its own record", file=sys.stderr)
    elif not pin_ref and pub is not None:
        print("gate-batch.py: NOTE — no --pin-ref: the human grant key and the set of owed gates "
              "are this working tree's, where a deleted gate leaves no trace; pass --pin-ref "
              "refs/remotes/origin/<default> (or a commit id) in a clone the checked change "
              "cannot write refs in", file=sys.stderr)


def repo_root():
    return Path(__file__).resolve().parent.parent.parent


def resolve_batch(run=None, file=None):
    if file:
        return Path(file)
    return repo_root() / "docs" / "runs" / run / "gate-batch.json"


def today_utc():
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(text, field):
    if not isinstance(text, str) or not DATE_RE.match(text):
        raise GateError(f"{field} must be YYYY-MM-DD, got {text!r}")
    try:
        return datetime.date(int(text[0:4]), int(text[5:7]), int(text[8:10]))
    except ValueError:
        raise GateError(f"{field} is not a real date: {text!r}")


def validate_gate(gate):
    if not isinstance(gate, dict):
        raise GateError(f"a gate must be an object, got {gate!r}")
    missing = [k for k in REQUIRED_GATE_KEYS if k not in gate]
    if missing:
        raise GateError(f"gate {gate.get('id', '?')} is missing {missing}")
    extra = sorted(set(gate) - set(REQUIRED_GATE_KEYS) - set(OPTIONAL_GATE_KEYS))
    if extra:
        raise GateError(f"gate {gate['id']} carries unknown fields {extra}")
    if not isinstance(gate["id"], str) or not GATE_ID_RE.match(gate["id"]):
        raise GateError(f"gate id must look like G1, got {gate['id']!r}")
    for key in ("title", "question"):
        if not isinstance(gate[key], str) or not gate[key].strip():
            raise GateError(f"gate {gate['id']}: {key} must be non-blank prose")
    asked = parse_date(gate["asked"], f"gate {gate['id']} asked")
    if gate["status"] not in STATUSES:
        raise GateError(f"gate {gate['id']}: status {gate['status']!r} "
                        f"is not one of {', '.join(STATUSES)}")
    for key in ("related", "blocking"):
        if (not isinstance(gate[key], list)
                or not all(isinstance(r, str) for r in gate[key])):
            raise GateError(f"gate {gate['id']}: {key} must be a list of refs")
    if gate["status"] == "owed":
        if gate["answer"] is not None or gate["answered"] is not None:
            raise GateError(f"gate {gate['id']} is owed but carries "
                            "answer/answered text")
    else:
        answered = parse_date(gate["answered"], f"gate {gate['id']} answered")
        if answered < asked:
            raise GateError(f"gate {gate['id']}: recorded {answered} "
                            f"precedes asked {asked}")
        if gate["status"] in ("answered", "waived") and not (
                isinstance(gate["answer"], str) and gate["answer"].strip()):
            raise GateError(f"gate {gate['id']}: {gate['status']} needs the "
                            "answer/waiver text recorded (overtaken alone may "
                            "leave it null when the question body says why)")
    source = gate.get("source")
    if source is not None and not (isinstance(source, str) and HUMAN_SOURCE.match(source)):
        raise GateError(f"gate {gate['id']}: source must be human:<name>, got {source!r}")
    if gate["status"] == "owed" and source is not None:
        raise GateError(f"gate {gate['id']} is owed but carries a source")
    sig = gate.get("grant_sig")
    if sig is not None and not (isinstance(sig, str) and GRANT_SIG_RE.match(sig)):
        raise GateError(f"gate {gate['id']}: grant_sig must be 128 lowercase hex characters")
    if gate["status"] == "owed" and sig is not None:
        raise GateError(f"gate {gate['id']} is owed but carries a grant_sig")


def validate_batch(data):
    if not isinstance(data, dict):
        raise GateError("the batch file must hold one JSON object")
    missing = [k for k in REQUIRED_BATCH_KEYS if k not in data]
    if missing:
        raise GateError(f"the batch is missing {missing}")
    extra = sorted(set(data) - set(REQUIRED_BATCH_KEYS))
    if extra:
        raise GateError(f"the batch carries unknown fields {extra}")
    if data["schema"] != SCHEMA_TAG:
        raise GateError(f"schema tag is {data['schema']!r}, want {SCHEMA_TAG!r}")
    for key in ("run_id", "run_title"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise GateError(f"batch {key} must be a non-blank string")
    for key in ("intro", "resolved_by_events"):
        if not isinstance(data[key], str):
            raise GateError(f"batch {key} must be a string")
    if not isinstance(data["gates"], list):
        raise GateError("batch gates must be a list")
    seen = set()
    for gate in data["gates"]:
        validate_gate(gate)
        if gate["id"] in seen:
            raise GateError(f"gate {gate['id']} appears twice")
        seen.add(gate["id"])


def load_batch(path):
    path = Path(path)
    if not path.is_file():
        raise GateError(f"no batch at {path} (init one with `init`)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise GateError(f"cannot read {path}: {e}")
    validate_batch(data)
    return data


def _atomic_write_text(path, text):
    """Crash-safe write: the bytes land in a tmp sibling first, and os.replace
    commits them — an interrupt leaves the old file (or nothing), never half
    a write."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def save_batch(path, data):
    validate_batch(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path,
                       json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def next_gate_id(data):
    nums = [int(g["id"][1:]) for g in data["gates"]]
    return f"G{(max(nums) + 1) if nums else 1}"


def find_gate(data, gid):
    for gate in data["gates"]:
        if gate["id"] == gid:
            return gate
    known = ", ".join(g["id"] for g in data["gates"]) or "(no gates yet)"
    raise GateError(f"no gate {gid} in this batch (known: {known})")


def init_batch(path, *, run_id, run_title, intro="", resolved=""):
    path = Path(path)
    if path.exists():
        raise GateError(f"{path} already exists (add gates to it)")
    data = {"schema": SCHEMA_TAG, "run_id": run_id, "run_title": run_title,
            "intro": intro, "gates": [], "resolved_by_events": resolved}
    save_batch(path, data)
    return data


def add_gate(data, *, title, question, gid=None, asked=None, related=(),
             blocking=()):
    gid = gid or next_gate_id(data)
    if not GATE_ID_RE.match(gid):
        raise GateError(f"gate id must look like G1, got {gid!r}")
    if any(g["id"] == gid for g in data["gates"]):
        raise GateError(f"gate {gid} already exists (ids are stable: "
                        "a renumber orphans parked-unit citations)")
    gate = {"id": gid, "title": title, "question": question,
            "asked": asked or today_utc().isoformat(), "status": "owed",
            "answer": None, "answered": None,
            "related": list(related), "blocking": list(blocking)}
    validate_gate(gate)
    data["gates"].append(gate)
    data["gates"].sort(key=lambda g: int(g["id"][1:]))
    return gate


def transition(data, gid, status, text, answered=None, source=None):
    if status not in TERMINAL:
        raise GateError(f"cannot transition to {status!r}")
    gate = find_gate(data, gid)
    if gate["status"] != "owed":
        raise GateError(f"gate {gid} is already {gate['status']}: only an "
                        "owed gate moves (the record is history, not a draft)")
    text = (text or "").strip()
    if status in ("answered", "waived") and not text:
        need = "the human's answer" if status == "answered" \
            else "the waiver reason"
        raise GateError(f"{status} gate {gid} needs {need} recorded")
    if source is not None and not HUMAN_SOURCE.match(source):
        raise GateError(f"gate {gid}: --source must be shaped human:<name>, got {source!r}")
    if status in ("answered", "waived") and not source:
        raise GateError(f"{status} gate {gid} needs --source human:<name>: who answered is "
                        "part of the record, or the answer is prose anyone could have typed")
    recorded = answered or today_utc().isoformat()
    if parse_date(recorded, "recorded") < parse_date(gate["asked"], "asked"):
        raise GateError(f"gate {gid}: recorded {recorded} precedes asked "
                        f"{gate['asked']}")
    gate["status"] = status
    gate["answer"] = text or None
    gate["answered"] = recorded
    if source:
        gate["source"] = source
    validate_gate(gate)
    return gate


def list_gates(data, status=None, blocking=None, pub=None, sound=False, anchored=None,
               commit=None):
    """Gates by status and, optionally, by blocked ref. The close rule waits
    on list(status="owed", blocking=<unit>): every owed blocker whatever its
    age — `stale` is only a reminder report and must never gate a close.
    Status is the EFFECTIVE one (W3-06): with a pinned key or on a sound lane
    an unverified terminal gate is owed; with an anchored batch (--pin-ref),
    every gate it carries that this batch lacks or altered is owed too."""
    if status is not None and status not in STATUSES:
        raise GateError(f"status {status!r} is not one of "
                        f"{', '.join(STATUSES)}")
    return [g for g, shown, refs, _ in close_view(data, pub, sound, anchored, commit)
            if (status is None or shown == status)
            and (blocking is None or blocking in refs)]


def stale_gates(data, days, today=None, pub=None, sound=False, anchored=None, commit=None):
    if days < 1:
        raise GateError(f"--days must be >= 1, got {days}")
    today = today or today_utc()
    stale = []
    for gate, shown, _, _ in close_view(data, pub, sound, anchored, commit):
        if shown != "owed":
            continue
        age = (today - parse_date(gate["asked"], "asked")).days
        if age >= days:
            stale.append((gate, age))
    stale.sort(key=lambda pair: pair[0]["asked"])
    return stale


def _expand_cite_token(token):
    """Every id a citation token names: a lone G<n>, or a G<a>-G<b> range
    expanded inclusively — a deleted intermediate inside a cited range must
    still warn, so endpoints alone are never enough."""
    match = CITE_RANGE_RE.match(token.strip())
    if not match:
        return CITE_ID_RE.findall(token)
    lo, hi = sorted((int(match.group(1)[1:]), int(match.group(2)[1:])))
    return [f"G{n}" for n in range(lo, hi + 1)]


def cited_gate_ids(run_dir):
    """Gate ids cited by unit manifests: {id: [manifest, ...]}.

    Only filename-anchored citations count ("gate-batch.json G3", or the
    pre-tooling "gate-batch.md G3") — prose that merely mentions a bare G3
    is not a citation and never warns.
    """
    cited = {}
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        return cited
    for manifest in sorted(run_dir.glob("*-manifest.json")):
        try:
            text = manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for match in CITE_RE.finditer(text):
            for ref in _expand_cite_token(match.group(1)):
                cited.setdefault(ref, [])
                if manifest.name not in cited[ref]:
                    cited[ref].append(manifest.name)
    return cited


def check_citations(data, run_dir):
    """Warnings for manifest citations no gate carries. Warning, not error:
    a dangling ref is a coordinator typo to fix, never a reason to fail a
    close that is otherwise evidence-bound."""
    known = {g["id"] for g in data["gates"]}
    cited = cited_gate_ids(run_dir)
    warnings = []
    for gid in sorted(set(cited) - known):
        manifests = ", ".join(cited[gid])
        warnings.append(f"warning: {manifests} cites gate {gid}, which no "
                        "gate in this batch carries")
    return warnings


ANNOTATION = {"answered": "Answered", "waived": "Waived",
              "overtaken": "Overtaken"}


def render_batch(data):
    """The .md view. Byte-stable: an owed gate renders exactly its heading
    plus its verbatim question, so a freshly migrated batch re-renders the
    original file byte-for-byte; only recorded answer text adds lines."""
    validate_batch(data)
    parts = [f"# Run-close human-gate batch \u2014 "
             f"{data['run_id']} ({data['run_title']})", "", data["intro"]]
    for gate in data["gates"]:
        parts += ["", f"## {gate['id']} \u00b7 {gate['title']}", "",
                  gate["question"]]
        if gate["answer"]:
            by = f" ({gate['source']})" if gate.get("source") else ""
            parts += ["", f"**{ANNOTATION[gate['status']]} "
                          f"{gate['answered']}{by}:** {gate['answer']}"]
    if data["resolved_by_events"]:
        parts += ["", "## Resolved by events (report only, no ask)", "",
                  data["resolved_by_events"]]
    return "\n".join(parts) + "\n"


def refresh_view(path, data):
    """Rewrite the sibling .md view from the store. Every CLI mutation calls
    this right after saving, so "md is a view" holds without the operator
    remembering a second command."""
    md = Path(path).parent / "gate-batch.md"
    _atomic_write_text(md, render_batch(data))
    return md


def _read_prose(direct, file, stdin_text, field):
    if direct is not None and file is not None:
        raise GateError(f"pass either {field} or {field}-file, not both")
    if file is not None:
        if file == "-":
            return stdin_text
        try:
            return Path(file).read_text(encoding="utf-8")
        except OSError as e:
            raise GateError(f"cannot read {file}: {e}")
    if direct is None:
        raise GateError(f"{field} is required ({field}-file - reads stdin)")
    return direct


def _split_refs(values):
    refs = []
    for value in values or ():
        refs += [r.strip() for r in value.split(",") if r.strip()]
    return refs


def _fmt_list(gate, shown=None, note=None, refs=None):
    shown = shown or gate["status"]
    refs = gate["blocking"] if refs is None else refs
    head = (f"{gate['id']} [{shown}] asked {gate['asked']} "
            f"\u00b7 {gate['title']}")
    if note:
        head += f" ({note})"
    elif shown != gate["status"]:
        head += (f" (recorded {gate['status']} {gate['answered']}, but not a verified human "
                 "answer \u2014 W3-06)")
    elif gate["status"] != "owed":
        head += f" \u2192 recorded {gate['answered']}"
    if refs:
        head += f" (blocking {', '.join(refs)})"
    return head


def _fmt_show(gate, shown=None, note=None):
    shown = shown or gate["status"]
    lines = [f"{gate['id']} \u00b7 {gate['title']}",
             f"status: {shown} (asked {gate['asked']})"]
    if note:
        lines.append(f"read as owed: {note}")
    elif shown != gate["status"]:
        lines.append(f"recorded {gate['status']}, but not a verified human answer \u2014 W3-06")
    if gate["status"] != "owed":
        lines.append(f"recorded {gate['answered']}: {gate['answer'] or '(no text)'}")
    if gate.get("source"):
        lines.append(f"source: {gate['source']}")
    if gate["related"]:
        lines.append("related: " + ", ".join(gate["related"]))
    if gate["blocking"]:
        lines.append("blocking: " + ", ".join(gate["blocking"]))
    lines += ["", gate["question"]]
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gate-batch.py",
        description="Run-close human gates as typed records (#419). "
                    "The JSON batch is the store; gate-batch.md is rendered. "
                    "NOT upstream decision-gates (orca orchestration "
                    "gate-create/gate-resolve/gate-list): this batch is LOCAL "
                    "to the run.",
        epilog="example: gate-batch.py --run 2026-09-14-clean-sweep-tracker "
               "list --status owed")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--run", metavar="DIR",
                        help="run directory under docs/runs/")
    target.add_argument("--file", metavar="PATH",
                        help="explicit batch JSON path (tests, scratch)")
    parser.add_argument("--pin-ref", default=None, metavar="REF",
                        help="the trust anchor: a commit id or a ref whose final target is "
                             "remote-tracking (refs/remotes/origin/main), resolved once; the "
                             "human grant key (.orca/human-grant-pubkey, via decisions.py) AND "
                             "this batch's set of gates are read at that commit, and a gate it "
                             "carries that this batch lacks or altered is owed. Trustworthy only "
                             "in a clone the checked change cannot write refs in (the "
                             "coordinator's fetch, a CI checkout); required on a sound lane "
                             "(ORCA_PROVENANCE set) — W3-06, PR #719 review")
    # The same flags after the subcommand (SUPPRESS keeps main-parser
    # values unless re-given): `list --run x` and `--run x list` both work.
    store = argparse.ArgumentParser(add_help=False)
    store.add_argument("--run", metavar="DIR", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    store.add_argument("--file", metavar="PATH", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    store.add_argument("--pin-ref", metavar="REF", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("init", parents=[store],
                        help="start an empty batch for a run",
                        description="Start an empty batch file.",
                        epilog="example: gate-batch.py --run my-run init "
                               "--run-id run_abc --title '2026-09-20 my run'")
    p.add_argument("--run-id", default=None,
                   help="stable run id (default: the --run directory name)")
    p.add_argument("--title", required=True, help="human run name")
    p.add_argument("--intro", default=None, help="standing prose for the batch")
    p.add_argument("--intro-file", default=None, metavar="PATH",
                   help="read --intro from a file (- for stdin)")
    p.add_argument("--resolved", default=None,
                   help="report-only resolved-by-events markdown block")
    p.add_argument("--resolved-file", default=None, metavar="PATH",
                   help="read --resolved from a file (- for stdin)")
    p.add_argument("--force-init-over-md", action="store_true",
                   help="overwrite the sibling gate-batch.md even when it "
                        "already exists (DESTROYS the pre-tooling view: "
                        "back it up first unless its gates are already "
                        "transcribed)")

    p = subs.add_parser("add", parents=[store],
                        help="park a new question (status owed)",
                        description="Park a new question. The id defaults to "
                                    "the next G<n>; pass --id to pin one "
                                    "while migrating an old batch.",
                        epilog="example: gate-batch.py --run my-run add "
                               "--title 'sign the manifest' --question-file - "
                               "--related '#386' --blocking '#386'")
    p.add_argument("--id", default=None, help="gate id, e.g. G1")
    p.add_argument("--title", required=True, help="heading suffix")
    p.add_argument("--question", default=None, help="the full ask")
    p.add_argument("--question-file", default=None, metavar="PATH",
                   help="read --question from a file (- for stdin)")
    p.add_argument("--asked", default=None,
                   help="ask date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--related", default=[], action="append",
                   help="related issue/PR ref (repeatable, comma-ok)")
    p.add_argument("--blocking", default=[], action="append",
                   help="blocked unit/issue ref (repeatable, comma-ok)")

    p = subs.add_parser("answer", parents=[store],
                        help="record the human's answer (owed -> answered)",
                        description="Record the human's answer on an owed gate.",
                        epilog="example: gate-batch.py --run my-run answer G1 "
                               "--answer 'the vault holds the key'")
    p.add_argument("gid", help="gate id, e.g. G1")
    p.add_argument("--answer", required=True, help="the human's answer")
    p.add_argument("--source", required=True, metavar="human:<name>",
                   help="who answered, as decisions.py records a grant (human:<name>)")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--grant-sig", default=None, metavar="HEX",
                   help="the human's signature from sign-answer; required once "
                        ".orca/human-grant-pubkey is pinned (W3-06)")

    p = subs.add_parser("waive", parents=[store],
                        help="record a waiver (owed -> waived)",
                        description="Record that the human ruled no answer "
                                    "needed, with the reason.",
                        epilog="example: gate-batch.py --run my-run waive G3 "
                               "--reason 'blind verdict suffices'")
    p.add_argument("gid", help="gate id, e.g. G3")
    p.add_argument("--reason", required=True, help="why no answer is needed")
    p.add_argument("--source", required=True, metavar="human:<name>",
                   help="who ruled it moot (human:<name>)")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--grant-sig", default=None, metavar="HEX",
                   help="the human's signature from sign-answer; required once "
                        ".orca/human-grant-pubkey is pinned (W3-06)")

    p = subs.add_parser("overtake", parents=[store],
                        help="record events answering first (owed -> overtaken)",
                        description="Record that events resolved the question "
                                    "before the human replied. The note is "
                                    "optional: when the question body already "
                                    "says what happened, there is nothing "
                                    "to add.",
                        epilog="example: gate-batch.py --run my-run overtake "
                               "G4 --note 'fixtures-plus-oracle merged'")
    p.add_argument("gid", help="gate id, e.g. G4")
    p.add_argument("--note", default=None,
                   help="what overtook the question (may be omitted)")
    p.add_argument("--source", default=None, metavar="human:<name>",
                   help="who recorded the overtaking (optional: events, not a person, answered)")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--grant-sig", default=None, metavar="HEX",
                   help="the human's signature from sign-answer; required once "
                        ".orca/human-grant-pubkey is pinned — an overtaken blocker leaves the "
                        "owed set too (W3-06)")

    p = subs.add_parser("sign-answer", parents=[store],
                        help="print the human's signature for one terminal record (W3-06)",
                        description="Sign, with the human grant seed (decisions.py "
                                    "grant-keygen), the exact record answer/waive/overtake "
                                    "will write: run, gate, status, text, date and source. "
                                    "Run it where the seed lives — never on a worker. Pass "
                                    "the same --date to both.",
                        epilog="example: gate-batch.py --run my-run sign-answer G1 "
                               "--status answered --answer 'the vault holds the key' "
                               "--source human:lia --date 2026-09-15 --key ~/.open-fleet/human-grant-key")
    p.add_argument("gid", help="gate id, e.g. G1")
    p.add_argument("--status", required=True, choices=list(TERMINAL),
                   help="the terminal status the record will carry")
    p.add_argument("--answer", default=None,
                   help="the answer / waiver reason / overtake note, exactly as recorded")
    p.add_argument("--source", default=None, metavar="human:<name>",
                   help="who answered (required for answered and waived)")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--key", required=True, metavar="SEED",
                   help="the human grant seed (decisions.py grant-keygen)")

    p = subs.add_parser("list", parents=[store],
                        help="list gates; warn on dangling manifest citations",
                        description="List gates (all, one status, or one "
                                    "blocked ref). Then scan sibling "
                                    "*-manifest.json files for "
                                    "gate-batch.json G<n> citations and warn "
                                    "on stderr about ids no gate carries.",
                        epilog="example: gate-batch.py --run my-run list "
                               "--status owed --blocking '#386'")
    p.add_argument("--status", default=None, choices=list(STATUSES),
                   help="show only this status (default: all)")
    p.add_argument("--blocking", default=None, metavar="REF",
                   help="show only gates blocking this unit/issue ref "
                        "(e.g. '#386'); with --status owed this is the "
                        "close wait-predicate: every owed blocker, "
                        "whatever its age)")

    p = subs.add_parser("stale", parents=[store],
                        help="report gates owed >= N days (default 7)",
                        description="Report owed gates asked >= N days ago. "
                                    "A report only: exit 0 either way, it "
                                    "notifies nobody.",
                        epilog="example: gate-batch.py --run my-run stale "
                               "--days 3")
    p.add_argument("--days", type=int, default=7,
                   help="flag gates owed this many days or more")
    p.add_argument("--today", default=None,
                   help="act as of YYYY-MM-DD (a testing aid, not a time "
                        "machine: production runs omit it)")

    p = subs.add_parser("show", parents=[store],
                        help="print one gate in full",
                        description="Print one gate: status, refs, and the "
                                    "full question.",
                        epilog="example: gate-batch.py --run my-run show G1")
    p.add_argument("gid", help="gate id, e.g. G1")

    p = subs.add_parser("render", parents=[store],
                        help="regenerate the .md view from the JSON store",
                        description="Regenerate gate-batch.md from the JSON "
                                    "store. The .md is a view, never edited "
                                    "by hand: every mutation re-renders it "
                                    "on save, and render --check verifies "
                                    "the two agree.",
                        epilog="example: gate-batch.py --run my-run render "
                               "--check")
    p.add_argument("--out", default=None, metavar="PATH",
                   help="write here instead of the sibling gate-batch.md "
                        "(- for stdout)")
    p.add_argument("--check", action="store_true",
                   help="exit 1 when the rendered view differs from --out "
                        "(default: the sibling .md)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        run, file = getattr(args, "run", None), getattr(args, "file", None)
        if bool(run) == bool(file):
            raise GateError("pass exactly one of --run DIR and --file PATH")
        path = resolve_batch(run, file)
        wants_stdin = [getattr(args, f, None) for f in
                       ("intro_file", "resolved_file", "question_file")]
        stdin_text = sys.stdin.read() if "-" in wants_stdin else ""
        if args.command == "init":
            run_id = args.run_id or (run if run
                                     else Path(file).parent.name)
            intro = _read_prose(args.intro, args.intro_file, stdin_text,
                                "--intro") if (args.intro is not None
                                               or args.intro_file) else ""
            resolved = _read_prose(args.resolved, args.resolved_file,
                                   stdin_text, "--resolved") \
                if (args.resolved is not None or args.resolved_file) else ""
            sibling = Path(path).parent / "gate-batch.md"
            if sibling.exists() and not getattr(args, "force_init_over_md",
                                                False):
                raise GateError(
                    f"{sibling} already exists (a pre-tooling view holding "
                    "the only gate record): transcribe its gates via "
                    "add/answer/waive/overtake after backing it up first, "
                    "or re-run with --force-init-over-md to destroy it")
            data = init_batch(path, run_id=run_id, run_title=args.title,
                               intro=intro.rstrip("\n"),
                               resolved=resolved.rstrip("\n"))
            refresh_view(path, data)
            print(f"initialized {path}")
            return 0
        data = load_batch(path)
        if args.command == "add":
            question = _read_prose(args.question, args.question_file,
                                   stdin_text, "--question")
            gate = add_gate(data, title=args.title,
                            question=question.rstrip("\n"), gid=args.id,
                            asked=args.asked,
                            related=_split_refs(args.related),
                            blocking=_split_refs(args.blocking))
            save_batch(path, data)
            refresh_view(path, data)
            print(f"added {gate['id']} (owed)")
            return 0
        if args.command in ("answer", "waive", "overtake"):
            status = {"answer": "answered", "waive": "waived",
                      "overtake": "overtaken"}[args.command]
            field = {"answer": "answer", "waive": "reason",
                     "overtake": "note"}[args.command]
            text = getattr(args, field)
            pub = read_trust(path, args.pin_ref)[0]
            gate = transition(data, args.gid, status, text,
                              answered=args.date, source=args.source)
            if pub is None and args.grant_sig:
                raise GateError("--grant-sig given but no human grant key is pinned "
                                "(.orca/human-grant-pubkey): a signature nothing can verify "
                                "fails closed (W3-06)")
            if pub is not None:
                if not args.grant_sig:
                    raise GateError(f"a human grant key is pinned, so {status} {args.gid} needs "
                                    "--grant-sig (gate-batch.py sign-answer, with the human's "
                                    "seed): an unsigned answer is one anyone could have typed "
                                    "(W3-06)")
                gate["grant_sig"] = args.grant_sig.strip().lower()
                if not answer_verified(data, gate, pub):
                    raise GateError(f"--grant-sig does not verify for {args.gid} as it would be "
                                    "recorded (run, gate, status, text, date and source are all "
                                    "signed) — not the pinned human's answer (W3-06)")
            save_batch(path, data)
            refresh_view(path, data)
            print(f"{gate['id']} -> {status}")
            return 0
        if args.command == "sign-answer":
            dec = _decisions()
            if dec is None:
                raise GateError("decisions.py (the human grant key's owner) is not beside this "
                                "script — nothing to sign with (W3-06)")
            try:
                seed = bytes.fromhex(Path(args.key).expanduser().read_text(
                    encoding="utf-8").strip())
            except (OSError, ValueError) as err:
                raise GateError(f"--key {args.key} is not a readable hex seed: {err}")
            if len(seed) != 32:
                raise GateError(f"--key {args.key} is not a 32-byte seed")
            trial = json.loads(json.dumps(data))  # sign the record transition() WOULD write
            gate = transition(trial, args.gid, args.status, args.answer,
                              answered=args.date, source=args.source)
            ed = dec._ed25519()
            print(ed.signature(answer_payload(trial, gate), seed, ed.publickey(seed)).hex())
            return 0
        if args.command == "list":
            pub, anchored, commit = read_trust(path, args.pin_ref)
            note_anchor(pub, args.pin_ref, anchored, commit)
            for gate, shown, refs, note in close_view(data, pub, bool(sound_lane()), anchored,
                                                      commit):
                if ((args.status is None or shown == args.status)
                        and (args.blocking is None or args.blocking in refs)):
                    print(_fmt_list(gate, shown, note, refs))
            for warning in check_citations(data, path.parent):
                print(warning, file=sys.stderr)
            return 0
        if args.command == "stale":
            today = parse_date(args.today, "--today") \
                if args.today else None
            pub, anchored, commit = read_trust(path, args.pin_ref)
            note_anchor(pub, args.pin_ref, anchored, commit)
            for gate, age in stale_gates(data, args.days, today, pub, bool(sound_lane()),
                                         anchored, commit):
                print(f"{gate['id']} owed {age} days "
                      f"(asked {gate['asked']}) \u00b7 {gate['title']}")
            return 0
        if args.command == "show":
            pub, anchored, commit = read_trust(path, args.pin_ref)
            note_anchor(pub, args.pin_ref, anchored, commit)
            for gate, shown, _, note in close_view(data, pub, bool(sound_lane()), anchored,
                                                   commit):
                if gate["id"] == args.gid:
                    print(_fmt_show(gate, shown, note))
                    return 0
            find_gate(data, args.gid)  # raises, naming the ids this batch does carry
        if args.command == "render":
            out = args.out or str(path.parent / "gate-batch.md")
            rendered = render_batch(data)
            if args.out == "-":
                sys.stdout.write(rendered)
                return 0
            if args.check:
                current = Path(out).read_text(encoding="utf-8") \
                    if Path(out).is_file() else None
                if current != rendered:
                    print(f"{out} is not what the store renders",
                          file=sys.stderr)
                    return 1
                print(f"{out} matches the store")
                return 0
            _atomic_write_text(out, rendered)
            print(f"rendered {out}")
            return 0
    except GateError as e:
        print(f"gate-batch.py: error: {e}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    sys.exit(main())

