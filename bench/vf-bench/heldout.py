#!/usr/bin/env python3
"""heldout.py — VF-Bench's held-out protocol: validation and the leakage check (#601).

The development corpus (`traps/*.json`) is public on purpose, so a verifier can be fitted to it.
The held-out split is a set of cases an independent holder keeps OUTSIDE this repository and
evaluates a pinned verifier against. `heldout-protocol.json` predeclares the splits, their
version digests, the planned release dates, the leakage checks and the holder role. This script
never reads held-out content from the repository; it only proves there is none:

  validate              the committed protocol is complete, its development pins equal gate.py's
                        and the corpus's, the holder role is filled honestly or not at all, the
                        published held-out counts and set digest are the digests file's, and each
                        recorded evaluation binds to its commit, verify.py blob and report bytes.
  vet CASE_DIR --pin C  holder side: every case is one the replay can run against the verifier
                        pinned at commit C, authored after it, and names the inventory row it
                        samples. Prints file names and counts, never case content (#601).
  digest CASE_DIR       holder side: publish DIGESTS of the held-out cases (raw and canonical-JSON
                        sha256, and the sha256 of the split's canary GUID), never their content.
                        Refuses a case that does not carry the canary. With --summary (and
                        --pin), it vets the set and also writes the set digest and the counts
                        per category, the figures the protocol publishes (#601).
  check --digests FILE  the leakage check: no committed blob at REV (or anywhere in history with
                        --all-history) is a held-out case — verbatim, reformatted, embedded as an
                        object in a larger JSON document — or carries the held-out canary.

Exit 0: valid / clean. Exit 1: invalid protocol, a leak, a case without its canary, or a case
that fails the vet. Exit 2: usage (unreadable digests, unknown revision).
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
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROTOCOL = HERE / "heldout-protocol.json"
PROTOCOL_ID = "vf-bench-heldout@1"
DIGESTS_KIND = "vf-bench-heldout-digests"
GUID_RE = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
GUID_TEXT_RE = re.compile(GUID_RE.pattern.decode("ascii"))
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# A role is filled by a person or left empty; these are what an empty role looks like in disguise.
PLACEHOLDERS = {"", "tbd", "tba", "n/a", "na", "none", "null", "unknown", "someone", "anyone",
                "nobody", "john doe", "jane doe", "evaluation maintainer", "holder"}
# A JSON document larger than this is not parsed; the check names it UNSCANNED and fails rather
# than passing it (PR #645 review). `check --max-json-bytes` raises it.
JSON_PARSE_LIMIT = 20 * 1024 * 1024
JSON_START = re.compile(r"\s*[\[{]")
JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
# What the holder publishes beside the digests: the set digest and the counts (#601).
SUMMARY_KIND = "vf-bench-heldout-summary"
HOLDER_KINDS = ("person", "ai-system")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$")
VERIFY_PATH = "runtime/scripts/verify.py"
REPLAY_SCHEMA = "vf-bench-replay@1"
# A held-out case's id and file name are opaque, so the evaluation report can list them (#601).
CASE_ID_RE = re.compile(r"^hv\d+-\d{3}$")
# The fields the replay's case schema reads (vfbench.py's gates and fixture builder) plus the
# held-out ones. Anything else is refused: a misspelt coordinator field is silently ignored by the
# gate and would measure a different case than the one written.
CASE_FIELDS = {"id", "class", "sound_expected", "note", "unit_class", "fixture",
               "coordinator_contract", "lighting", "no_gh", "execute_nc", "nc_command", "repo",
               "dispatch", "gh_stub", "gh_reviews", "manifest", "expect_reason", "neighbour",
               "requires_commits", "contract_source", "contract_digest", "base",
               "canary", "authored_at", "verifier_pin", "inventory_site"}
# Read only for a run-time fixture: on a static case the sound gate never passes them on.
FIXTURE_ONLY_FIELDS = {"coordinator_contract", "lighting", "no_gh", "dispatch", "gh_stub",
                       "gh_reviews"}
# What a held-out case adds to, or renames in, a development case. Dropped before the two are
# compared, so what is compared is the gaming move as written (#601).
HELDOUT_META = {"id", "class", "canary", "authored_at", "verifier_pin", "inventory_site", "note",
                "neighbour", "repo"}


class UsageError(Exception):
    pass


def canonical(obj):
    """The canonical-JSON bytes of a case: sorted keys, no whitespace, UTF-8. A reformatted copy
    of a case (indentation, key order, escapes) hashes the same; a changed one does not."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------------------------

def _gate():
    spec = importlib.util.spec_from_file_location("vfbench_gate_heldout", HERE / "gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def validate(protocol, gate=None, traps_dir=None):
    """Every problem with a protocol document, as strings (empty = valid). A section of the wrong
    JSON type is named and read as empty, never raised (PR #665 review sweep)."""
    if not isinstance(protocol, dict):
        return ["the protocol must be a JSON object"]
    gate = gate or _gate()
    traps_dir = Path(traps_dir) if traps_dir else HERE / "traps"
    errors = _type_errors(protocol)
    if protocol.get("protocol") != PROTOCOL_ID:
        errors.append(f"protocol is {protocol.get('protocol')!r}, not {PROTOCOL_ID!r}")
    splits = _obj(protocol.get("splits"))
    dev, held = _obj(splits.get("development")), _obj(splits.get("heldout"))
    if not dev or not held:
        errors.append("the protocol must declare both a development and a heldout split")
    traps = []
    for path in sorted(traps_dir.glob("*.json")):
        try:
            traps.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, RecursionError) as exc:
            # One unreadable case is named; the rest of the protocol is still checked (PR #645).
            errors.append(f"cannot read corpus case {path.name}: {type(exc).__name__}: {exc}"[:300])
    expect = {
        "version": gate.EXPECTED_VERSION,
        "canary_guid": gate.EXPECTED_CANARY_GUID,
        "corpus_sha256": gate.EXPECTED_CORPUS_SHA256,
        "cases": len(traps),
        "traps": sum(1 for t in traps if t.get("sound_expected") == "RED"),
        "valid_controls": sum(1 for t in traps if t.get("sound_expected") == "GREEN"),
        "committed": True,
    }
    for key, want in expect.items():
        if dev and dev.get(key) != want:
            errors.append(f"development split {key} is {dev.get(key)!r}; the shipped corpus and "
                          f"gate.py say {want!r} — a corpus change updates the protocol in the same PR")
    try:
        digest = gate.corpus_digest(traps_dir)
    except OSError as exc:
        digest = None
        errors.append(f"cannot compute the corpus digest: {exc}")
    if dev and digest is not None and digest != dev.get("corpus_sha256"):
        errors.append("development split corpus_sha256 is not the digest of traps/*.json")
    if held:
        if held.get("committed") is not False:
            errors.append("the heldout split must declare committed: false — held-out content is "
                          "never committed beside the solver before its evaluation")
        published = held.get("published_digests")
        if published is not None:
            path = ROOT / str(published)
            if not path.is_file():
                errors.append(f"heldout published_digests names {published}, which does not exist")
            else:
                try:
                    load_digests(path)
                except UsageError as exc:
                    errors.append(f"heldout published_digests: {exc}")
    temporal = _obj(protocol.get("temporal"))
    if not str(temporal.get("rule") or "").strip():
        errors.append("the protocol must state its temporal rule")
    dates = _obj(protocol.get("release_dates"))
    if "planned" not in str(dates.get("label") or "").lower():
        errors.append("release_dates must be labelled as planned")
    milestones = _object_list(dates.get("milestones"))
    if not milestones:
        errors.append("release_dates must name at least one milestone")
    for m in milestones:
        name = m.get("milestone") or "?"
        if not DATE_RE.match(str(m.get("date") or "")):
            errors.append(f"milestone {name!r} has no YYYY-MM-DD date")
        if m.get("status") not in ("planned", "done"):
            errors.append(f"milestone {name!r} status is {m.get('status')!r}, not planned or done")
        if m.get("status") == "done" and not str(m.get("evidence") or "").strip():
            errors.append(f"milestone {name!r} is marked done without evidence")
    checks = _object_list(protocol.get("leakage_checks"))
    ids = {c.get("id") for c in checks if isinstance(c.get("id"), str)}
    for need in ("digest-scan", "canary-scan", "history-scan", "temporal"):
        if need not in ids:
            errors.append(f"leakage check {need!r} is not declared")
    for c in checks:
        if not str(c.get("detects") or "").strip():
            errors.append(f"leakage check {c.get('id')!r} does not say what it detects")
        command = str(c.get("command") or "")
        if "heldout.py" in command and not str(c.get("limits") or "").strip():
            errors.append(f"leakage check {c.get('id')!r} runs a scan but states no limits: a "
                          "check may promise only what it catches (PR #645 review)")
        if "heldout.py" in command and not (HERE / "heldout.py").is_file():
            errors.append(f"leakage check {c.get('id')!r} names a command that does not exist")
    holder = _obj(protocol.get("holder"))
    assigned, state = holder.get("assigned"), holder.get("state")
    if not str(holder.get("role") or "").strip():
        errors.append("the holder role is not described")
    if assigned is None:
        if state != "unfilled":
            errors.append(f"no holder is assigned, so the role's state must be 'unfilled', not {state!r}")
    elif not isinstance(assigned, str) or assigned.strip().lower() in PLACEHOLDERS:
        errors.append(f"holder.assigned is {assigned!r}: a role nobody holds stays null, never a "
                      "placeholder name")
    elif state != "assigned":
        errors.append(f"a holder is named, so the role's state must be 'assigned', not {state!r}")
    else:
        errors += _assigned_holder_errors(holder)
    errors += _published_errors(protocol)
    errors += _evaluation_errors(protocol)
    errors += _milestone_state_errors(protocol)
    return errors


def _obj(value):
    """A JSON object as a dict; anything else reads as an empty one (its type is named by
    _type_errors)."""
    return value if isinstance(value, dict) else {}


def _object_list(value):
    """The objects in a JSON list; anything else reads as no objects."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _type_errors(protocol):
    """Every protocol section whose JSON type is not the one the protocol declares (PR #665
    review sweep): each was a crash before, out of a membership test or an attribute read."""
    errors = []
    for key in ("splits", "temporal", "release_dates", "holder"):
        if key in protocol and not isinstance(protocol[key], dict):
            errors.append(f"{key} must be a JSON object")
    for key in ("development", "heldout"):
        if key in _obj(protocol.get("splits")) and not isinstance(protocol["splits"][key], dict):
            errors.append(f"splits.{key} must be a JSON object")
    if "pinned_verifier" in _obj(protocol.get("temporal")) and not isinstance(
            protocol["temporal"]["pinned_verifier"], dict):
        errors.append("temporal.pinned_verifier must be a JSON object")
    for where, value in (("release_dates.milestones", _obj(protocol.get("release_dates")).get("milestones")),
                         ("leakage_checks", protocol.get("leakage_checks"))):
        if value is not None and not (isinstance(value, list)
                                      and all(isinstance(v, dict) for v in value)):
            errors.append(f"{where} must be a list of JSON objects")
    for m in _object_list(_obj(protocol.get("release_dates")).get("milestones")):
        for key in ("id", "milestone", "date", "status"):
            if key in m and not isinstance(m[key], str):
                errors.append(f"a milestone's {key} must be a string")
    for c in _object_list(protocol.get("leakage_checks")):
        if not isinstance(c.get("id"), str):
            errors.append("every leakage check needs a string id")
    return errors


def _text(value):
    """A non-empty string, or a non-empty list of non-empty strings; anything else is absent."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value):
        return " ".join(value)
    return ""


def _assigned_holder_errors(holder):
    """A filled role says who designated it, when, why the holder is independent and where that
    independence stops (#601). An AI system also names its model, its client and who runs it: it
    is not a person, and the protocol must not let it read as one."""
    errors = []
    for key in ("kind", "designated_by", "designated_on", "independence_evidence", "limits"):
        if not _text(holder.get(key)):
            errors.append(f"an assigned holder must record {key}")
    if holder.get("kind") and holder.get("kind") not in HOLDER_KINDS:
        errors.append(f"holder.kind is {holder.get('kind')!r}, not one of {', '.join(HOLDER_KINDS)}")
    if holder.get("designated_on") and not DATE_RE.match(str(holder["designated_on"])):
        errors.append("holder.designated_on is not a YYYY-MM-DD date")
    if holder.get("kind") == "ai-system":
        for key in ("model", "client", "operated_by"):
            if not _text(holder.get(key)):
                errors.append(f"an AI-system holder must record {key}: it is not a person")
    return errors


def set_digest(digests):
    """The held-out set's identity: sha256 over its cases' raw sha256 digests, sorted, one per
    line. The replay recomputes it from the files it is handed, so it scores exactly the set whose
    digests were published (#601)."""
    return sha256("".join(f"{c['raw_sha256']}\n" for c in sorted(
        digests["cases"], key=lambda c: c["raw_sha256"])).encode("ascii"))


def _when(stamp):
    """An ISO-8601 timestamp with its offset as an aware datetime, or None — also for one shaped
    right that names no instant, such as 2026-02-30 (PR #665 review)."""
    if not isinstance(stamp, str) or not TIMESTAMP_RE.match(stamp):
        return None
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def resolve_pin(repo, commit):
    """{commit, verify_blob, committed_at} for the verifier revision a held-out version is pinned
    to, read from git: the temporal rule compares authoring times with `committed_at`."""
    try:
        full = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}").decode().strip()
        blob = _git(repo, "rev-parse", "--verify", "--quiet", f"{full}:{VERIFY_PATH}").decode().strip()
        when = _git(repo, "show", "-s", "--format=%cI", full).decode().strip()
    except UsageError:
        raise UsageError(f"{commit!r} is not a commit holding {VERIFY_PATH} in {repo}") from None
    return {"commit": full, "verify_blob": blob, "committed_at": when}


def _published_errors(protocol):
    """Published digests bind the split's figures: the set digest, the case and category counts
    and the authoring window are the digests file's and the holder's summary, and they fall after
    the pinned verifier revision (the temporal rule)."""
    held = _obj(_obj(protocol.get("splits")).get("heldout"))
    published = held.get("published_digests")
    if published is None:
        return []
    errors = []
    if _obj(protocol.get("holder")).get("state") != "assigned":
        errors.append("held-out digests are published but no holder is assigned: unseen cases "
                      "need someone who holds them")
    try:
        doc = load_digests(ROOT / str(published))
    except UsageError:
        return errors  # named by validate itself
    if held.get("set_sha256") != set_digest(doc):
        errors.append("heldout set_sha256 is not the set digest of the published digests file")
    if held.get("cases") != len(doc["cases"]):
        errors.append(f"heldout cases is {held.get('cases')!r}; the published digests list "
                      f"{len(doc['cases'])}")
    traps, controls = held.get("traps"), held.get("valid_controls")
    if not (isinstance(traps, int) and isinstance(controls, int) and traps + controls == len(doc["cases"])):
        errors.append("heldout traps + valid_controls must equal the published case count")
    if not (isinstance(controls, int) and controls >= 1):
        errors.append("the held-out split carries no valid control, so it cannot measure false "
                      "rejection")
    cats = held.get("by_category")
    if not (isinstance(cats, dict) and cats and all(
            isinstance(v, dict) and set(v) == {"traps", "valid_controls"}
            and all(isinstance(n, int) and n >= 0 for n in v.values()) for v in cats.values())):
        errors.append("heldout by_category must map each category to {traps, valid_controls}")
    elif (sum(v["traps"] for v in cats.values()), sum(v["valid_controls"] for v in cats.values())) \
            != (traps, controls):
        errors.append("heldout by_category does not sum to the split's traps and valid_controls")
    pin = _obj(_obj(protocol.get("temporal")).get("pinned_verifier"))
    start, end = _when(held.get("authored_from")), _when(held.get("authored_to"))
    if start is None or end is None or start > end:
        errors.append("heldout authored_from / authored_to must be ISO-8601 timestamps in order")
    if not (HEX40.match(str(pin.get("commit") or "")) and HEX40.match(str(pin.get("verify_blob") or ""))
            and _when(pin.get("committed_at"))):
        errors.append("temporal.pinned_verifier must name a commit, its verify.py blob and its "
                      "committed_at timestamp")
        return errors
    try:
        real = resolve_pin(ROOT, pin["commit"])
    except UsageError as exc:
        errors.append(f"temporal.pinned_verifier cannot be bound: {exc}")
        return errors
    if (real["verify_blob"], _when(real["committed_at"])) != (pin["verify_blob"],
                                                              _when(pin["committed_at"])):
        errors.append("temporal.pinned_verifier's verify_blob or committed_at is not what git "
                      "records for its commit")
    if start is not None and start <= _when(pin["committed_at"]):
        errors.append("a held-out case was authored before the verifier revision it evaluates was "
                      "pinned: the temporal rule is broken")
    return errors


def _evaluation_errors(protocol):
    """Each recorded evaluation binds: its report hashes to the recorded sha256, is a held-out
    replay of the recorded commit, ran the pinned verify.py blob, selected the WHOLE published
    set and, when complete, scored all of it, and git agrees the commit holds that blob (#601). A
    report edited after the run, a run at another revision, or a subset run does not bind."""
    evaluations = protocol.get("evaluations")
    if evaluations is None:
        return []
    if not isinstance(evaluations, list):
        return ["evaluations must be a list"]
    held = _obj(_obj(protocol.get("splits")).get("heldout"))
    pin = _obj(_obj(protocol.get("temporal")).get("pinned_verifier"))
    errors = []
    for i, ev in enumerate(evaluations):
        where = f"evaluation {i + 1}"
        if not isinstance(ev, dict):
            errors.append(f"{where} is not an object")
            continue
        if held.get("published_digests") is None:
            errors.append(f"{where} is recorded but no held-out digests are published")
        if ev.get("version") != held.get("version"):
            errors.append(f"{where} names version {ev.get('version')!r}, not the split's")
        if not DATE_RE.match(str(ev.get("date") or "")):
            errors.append(f"{where} has no YYYY-MM-DD date")
        elif _when(held.get("authored_to")) and ev["date"] < held["authored_to"][:10]:
            errors.append(f"{where} is dated before the last case was authored")
        if not (HEX40.match(str(ev.get("revision") or "")) and HEX40.match(str(ev.get("verify_blob") or ""))
                and HEX64.match(str(ev.get("report_sha256") or "")) and isinstance(ev.get("complete"), bool)):
            errors.append(f"{where} must record revision, verify_blob, report, report_sha256 and complete")
            continue
        if ev["verify_blob"] != pin.get("verify_blob"):
            errors.append(f"{where} ran verify.py blob {ev['verify_blob'][:12]}, not the pinned "
                          f"{str(pin.get('verify_blob'))[:12]}")
        try:
            blob = _git(ROOT, "rev-parse", "--verify", "--quiet",
                        f"{ev['revision']}:{VERIFY_PATH}").decode().strip()
        except UsageError:
            blob = None
        if blob != ev["verify_blob"]:
            errors.append(f"{where}: git does not hold verify.py blob {ev['verify_blob'][:12]} at "
                          f"{ev['revision'][:12]}")
        report_path = ev.get("report")
        try:
            raw = (ROOT / report_path).read_bytes() if isinstance(report_path, str) and report_path else None
        except (OSError, ValueError):  # unreadable, a directory, or a NUL in the path
            raw = None
        if raw is None:
            errors.append(f"{where}: report {ev.get('report')!r} cannot be read")
            continue
        if sha256(raw) != ev["report_sha256"]:
            errors.append(f"{where}: report {ev['report']} does not hash to report_sha256")
        try:
            report = json.loads(raw)
        except (ValueError, RecursionError):
            report = None
        if not isinstance(report, dict) or report.get("schema") != REPLAY_SCHEMA:
            errors.append(f"{where}: report {ev['report']} is not a {REPLAY_SCHEMA} report")
            continue
        facts = {
            "a held-out replay": _obj(report.get("protocol")).get("split") == "heldout",
            "of the recorded revision": _obj(report.get("revision")).get("commit") == ev["revision"],
            "of the pinned verify.py blob": _obj(_obj(report.get("versions")).get("blobs")).get(
                VERIFY_PATH) == ev["verify_blob"],
            "of the published set": _obj(report.get("heldout")).get("set_sha256")
            == held.get("set_sha256"),
            "whose completeness is recorded": _obj(report.get("verdict")).get("ok") is ev["complete"],
        }
        for fact, holds in facts.items():
            if not holds:
                errors.append(f"{where}: report {ev['report']} is not {fact}")
        errors += [f"{where}: report {ev['report']} {e}"
                   for e in _whole_set_errors(report, held, ev["complete"])]
    return errors


# The gates a replay always runs on every case: they cannot decline one, so a complete held-out
# evaluation shows each of them scoring the whole split in every run. An adapter may declare a
# case UNSUPPORTED, so its counts do not decide completeness.
_BUILT_IN_TIERS = ("measured", "synthetic-baseline")


def _whole_set_errors(report, held, complete):
    """Why a report is not an evaluation of the WHOLE published set (PR #665 review, P1): the
    preflight checks every published digest even when `--cases` selects a few, and the report
    carries the full set digest either way, so a one-case run looked complete. A recorded
    evaluation selects the whole split, per split, and a complete one scores all of it."""
    protocol, corpus = report.get("protocol"), report.get("corpus")
    protocol = protocol if isinstance(protocol, dict) else {}
    corpus = corpus if isinstance(corpus, dict) else {}
    traps, controls, cases = held.get("traps"), held.get("valid_controls"), held.get("cases")
    errors = []
    if protocol.get("selection"):
        errors.append("is a subset run (--cases): a subset of the set is not an evaluation of it")
    selected = tuple(corpus.get(k) for k in ("selected", "total", "traps", "valid_controls"))
    if selected != (cases, cases, traps, controls):
        errors.append(f"selected {selected[0]!r} of {selected[1]!r} case(s) ({selected[2]!r} traps, "
                      f"{selected[3]!r} valid controls); the published split is {cases!r} "
                      f"({traps!r}, {controls!r})")
    if not complete:
        return errors
    configs = report.get("configurations")
    configs = configs if isinstance(configs, dict) else {}
    built_in = {n: c for n, c in configs.items()
                if isinstance(c, dict) and c.get("tier") in _BUILT_IN_TIERS}
    if not any(c.get("tier") == "measured" for c in built_in.values()):
        errors.append("is marked complete, but no measured verifier scored it")
    for name, cfg in sorted(built_in.items()):
        runs = cfg.get("runs") if isinstance(cfg.get("runs"), list) else []
        if not runs:
            errors.append(f"is marked complete, but {name} records no run")
        for n, run in enumerate(runs, 1):
            run = run if isinstance(run, dict) else {}
            got = tuple((run.get(k) if isinstance(run.get(k), dict) else {}).get("of")
                        for k in ("false_acceptance", "false_rejection"))
            if got != (traps, controls):
                errors.append(f"is marked complete, but {name} scored {got[0]!r} trap(s) and "
                              f"{got[1]!r} valid control(s) in run {n}; the split publishes "
                              f"{traps!r} and {controls!r}")
    return errors


def _milestone_state_errors(protocol):
    """A milestone with an id says whether it happened, and the protocol's own state must agree:
    a done milestone the protocol does not show, or a planned one it already shows, is a date
    that lies (#601)."""
    milestones = [m for m in _object_list(_obj(protocol.get("release_dates")).get("milestones"))
                  if isinstance(m.get("id"), str) and m["id"]]
    held = _obj(_obj(protocol.get("splits")).get("heldout"))
    evaluations = protocol.get("evaluations") if isinstance(protocol.get("evaluations"), list) else []
    happened = {
        "holder-assigned": _obj(protocol.get("holder")).get("state") == "assigned",
        "digests-published": held.get("published_digests") is not None,
        "evaluated": bool(evaluations),
    }
    errors = []
    for m in milestones:
        did = happened.get(m["id"])
        if did is None:
            continue
        if did and m.get("status") != "done":
            errors.append(f"milestone {m['id']!r} is still {m.get('status')!r}, but the protocol "
                          "shows it happened")
        if not did and m.get("status") == "done":
            errors.append(f"milestone {m['id']!r} is marked done, but the protocol does not show it")
        if (m["id"] == "evaluated" and m.get("status") == "done"
                and m.get("date") not in [e.get("date") for e in evaluations if isinstance(e, dict)]):
            errors.append("milestone 'evaluated' is dated unlike every recorded evaluation")
    return errors


# ---------------------------------------------------------------------------------------------
# digest (holder side)
# ---------------------------------------------------------------------------------------------

def _strings(node):
    """Every string in a parsed JSON value, keys included. Walked with an explicit stack, never
    recursion: json.loads accepts documents nested deeper than Python's recursion limit
    (PR #645 review)."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield key
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def digest_cases(case_dir, canary):
    """(digests document, problems). Each case must carry the split's canary GUID, so a copy of
    it that keeps the canary as text is findable without publishing the case itself (the limits
    are in heldout-protocol.json). The holder's tool accepts exactly what the scanner finds: the
    case is PARSED in any encoding json.loads reads and the GUID is looked for, case-insensitively,
    in its strings, so uppercase, UTF-16 and JSON-escaped canaries all count; and a case the
    scanner could never match, anything but a JSON object, is refused (PR #645 review)."""
    canary = canary.lower()
    files = sorted(Path(case_dir).glob("*.json"))
    if not files:
        raise UsageError(f"{case_dir} holds no *.json cases")
    problems, entries = [], []
    for f in files:
        try:
            raw = f.read_bytes()
        except OSError as exc:  # unreadable, a directory, a symlink loop (PR #645 review)
            problems.append(f"{f.name}: cannot be read ({exc.strerror or exc})")
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            problems.append(f"{f.name}: not JSON")
            continue
        except (ValueError, RecursionError) as exc:  # valid JSON json cannot convert, or too deep
            problems.append(f"{f.name}: JSON that cannot be read: {type(exc).__name__}"
                            + (" (nested too deep to read)" if isinstance(exc, RecursionError) else ""))
            continue
        if not isinstance(obj, dict):
            problems.append(f"{f.name}: not a JSON object; the scan matches objects, so it could "
                            "never find this case")
            continue
        if not any(canary in s.lower() for s in _strings(obj)):
            problems.append(f"{f.name}: does not carry the split's canary GUID")
        try:
            entries.append({"raw_sha256": sha256(raw), "canonical_sha256": sha256(canonical(obj))})
        except (RecursionError, UnicodeEncodeError) as exc:
            problems.append(f"{f.name}: cannot be put in canonical form ({type(exc).__name__}: "
                            "nested too deep, or a string with an unpaired surrogate)")
    doc = {"kind": DIGESTS_KIND, "protocol": PROTOCOL_ID,
           "canary_sha256": sha256(canary.encode("utf-8")),
           "cases": sorted(entries, key=lambda e: e["raw_sha256"])}
    return doc, problems


def _sibling(name, alias, where=HERE):
    spec = importlib.util.spec_from_file_location(alias, Path(where) / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# What the pinned bench's fixture builders load: vfbench.py itself, its corpus, and the coordinator
# tools it plays (dispatch signing, Ed25519, verify.py's own custody probe).
PINNED_PATHS = ("bench/vf-bench", "runtime/scripts")


@contextlib.contextmanager
def pinned_bench(repo, commit):
    """The PINNED revision's bench/vf-bench and runtime/scripts, written from git's objects into a
    temporary directory (PR #665 review, P2): `vet --pin` read the pinned README but built and
    compared cases with this checkout's code, so it could pass a case the pinned replay cannot
    run. The replay scores the pinned revision's export; the vet now judges against the same
    files. Plumbing only: no checkout, no index, no hook runs."""
    with tempfile.TemporaryDirectory(prefix="vfbench-heldout-pin-") as tmp:
        root = Path(tmp).resolve()
        entries = []
        for entry in _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--",
                          *PINNED_PATHS).split(b"\0"):
            if entry:
                meta, path = entry.split(b"\t", 1)
                mode, kind, sha = meta.decode().split()
                if kind == "blob":
                    entries.append((mode, sha, os.fsdecode(path)))
        blobs = read_blobs(repo, sorted({sha for _, sha, _ in entries}))
        for mode, sha, path in entries:
            target = (root / path).resolve() if mode != "120000" else root / path
            if not target.is_relative_to(root) or blobs.get(sha) is None:
                raise UsageError(f"{commit}: {path} cannot be written from this repository's objects")
            target.parent.mkdir(parents=True, exist_ok=True)
            if mode == "120000":
                target.symlink_to(os.fsdecode(blobs[sha]))
            else:
                target.write_bytes(blobs[sha])
                target.chmod(0o755 if mode == "100755" else 0o644)
        bench = root / "bench" / "vf-bench"
        if not (bench / "vfbench.py").is_file():
            raise UsageError(f"{commit} holds no bench/vf-bench/vfbench.py to vet against")
        yield bench


def _pinned_file(repo, commit, path):
    """The bytes of `path` at `commit`, or None when it is not a file there or is no plain
    repository-relative path: a static case's contract is judged at the pin, as the replay's
    export holds it, never in this checkout's working tree (PR #665 review)."""
    rel = PurePosixPath(path) if isinstance(path, str) and path and "\0" not in path else None
    if rel is None or rel.is_absolute() or ".." in rel.parts:
        return None
    try:
        sha = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}:{rel.as_posix()}").decode().strip()
        if _git(repo, "cat-file", "-t", sha).decode().strip() != "blob":
            return None
    except UsageError:
        return None
    return read_blobs(repo, [sha]).get(sha)


def _read_case(f):
    """(parsed object, problem): the case the replay will load, or why it never will."""
    try:
        obj = json.loads(f.read_bytes())
    except OSError as exc:
        return None, f"cannot be read ({exc.strerror or exc})"
    except (ValueError, RecursionError):
        return None, "not JSON the replay can load"
    return (obj, None) if isinstance(obj, dict) else (None, "not a JSON object")


def _move(case):
    """A case without its held-out metadata, its review repository name and its unit name."""
    move = {k: v for k, v in case.items() if k not in HELDOUT_META}
    if isinstance(move.get("manifest"), dict):
        move["manifest"] = {k: v for k, v in move["manifest"].items() if k != "unit"}
    return move


def _leaves(node):
    """{(path, value)} for every scalar in a parsed JSON value, walked without recursion."""
    out, stack = set(), [(node, "")]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            stack.extend((v, f"{path}.{k}") for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((v, f"{path}[{i}]") for i, v in enumerate(node))
        else:
            out.add((path, json.dumps(node)))
    return out


def development_moves(traps_dir=None):
    return [_move(json.loads(f.read_text(encoding="utf-8")))
            for f in sorted(Path(traps_dir or HERE / "traps").glob("*.json"))]


def novelty(cases, dev_moves):
    """How far the set is from the public corpus, in numbers only (#601): for each case, the
    leaves (scalar values by path) by which it differs from its NEAREST development case once
    held-out metadata is dropped; zero is a copy. Counts, never which case or what differs."""
    dev = [_leaves(d) for d in dev_moves]
    diffs = sorted(min(len(_leaves(_move(c)) ^ d) for d in dev) for c in cases.values()) if dev else []
    if not diffs:
        return None
    return {"copies": sum(1 for d in diffs if d == 0), "differing_leaves_min": diffs[0],
            "differing_leaves_median": diffs[len(diffs) // 2], "differing_leaves_max": diffs[-1]}


def _unrendered(value):
    """How many `{{token}}` placeholders survive rendering: each is a fact the fixture never
    supplies, so verify.py would judge a literal `{{...}}` instead of the case written."""
    return len(re.findall(r"\{\{[^{}]*\}\}", json.dumps(value)))


def vet_cases(case_dir, pin, repo=ROOT):
    """(problems, cases) for a held-out set, checked the way the replay will run it against the
    verifier pinned at `pin` (a resolve_pin dict), WITHOUT running the verifier (#601).

    Every problem is `file: reason` and never quotes a case: the holder runs this while authoring,
    and anyone may run it on the holder's directory without seeing what it holds. Each case:
    carries only fields the replay reads, has an opaque id equal to its file name, names its
    category (a check in the pinned inventory) and, for a trap, the ONE inventory row it samples
    (`inventory_site`: a development trap class or a refusal stem of that row) and the refusal it
    earns (`expect_reason`); records `authored_at` after the pin and `verifier_pin` equal to it;
    and, for a run-time fixture, builds and renders with no placeholder left over."""
    with pinned_bench(repo, pin["commit"]) as bench:
        return _vet_against(case_dir, pin, repo, bench)


def _vet_against(case_dir, pin, repo, bench):
    """vet_cases, with the pinned bench written out at `bench`. The inventory PARSER is this
    runner's, as the replay parses the exported README with its own; everything it parses, and
    every builder, corpus case and repository path a case names, is the pin's."""
    readme = (bench / "README.md").read_text(encoding="utf-8", errors="replace")
    replay = _sibling("replay.py", "vfbench_replay_for_heldout")
    vf = _sibling("vfbench.py", "vfbench_for_heldout_pinned", bench)
    rows = replay.inventory_rows(readme) or []
    checks = {c for r in rows for c in r["checks"]}
    pinned_at, now = _when(pin["committed_at"]), datetime.now(timezone.utc)
    files = sorted(Path(case_dir).glob("*.json"))
    if not files:
        raise UsageError(f"{case_dir} holds no *.json cases")
    problems, cases = [], {}
    for f in files:
        obj, why = _read_case(f)
        if why:
            problems.append(f"{f.name}: {why}")
            continue
        cases[f.name] = obj

    def bad(name, why):
        problems.append(f"{name}: {why}")

    ids = [c.get("id") for c in cases.values()]
    public = {json.dumps(m, sort_keys=True) for m in development_moves(bench / "traps")}
    ctx = SimpleNamespace(cases=cases, ids=ids, public=public, checks=checks, rows=rows,
                          replay=replay, vf=vf, pin=pin, pinned_at=pinned_at, now=now, repo=repo)
    for name, c in cases.items():
        try:
            _vet_one(name, c, ctx, bad)
        except Exception as exc:  # one case never stops the vet; its reason names no content
            bad(name, f"the vet could not check it ({type(exc).__name__})")
    _vet_rendering(vf, cases, bad)
    return problems, cases


def _vet_one(name, c, ctx, bad):
    """Every check on ONE case. A field of the wrong JSON type is refused by name before any
    membership test that would raise on it (PR #665 review)."""
    if json.dumps(_move(c), sort_keys=True) in ctx.public:
        bad(name, "a copy of a development case once the held-out fields are dropped: it "
                  "measures nothing the public corpus does not")
    extra = sorted(set(c) - CASE_FIELDS)
    if extra:
        bad(name, f"{len(extra)} field(s) the replay does not read")
    if not (isinstance(c.get("id"), str) and CASE_ID_RE.match(c["id"]) and name == c["id"] + ".json"):
        bad(name, "id must be opaque (hv<version>-<3 digits>) and the file named <id>.json")
    elif ctx.ids.count(c["id"]) > 1:
        bad(name, "its id is not unique in the set")
    if not isinstance(c.get("class"), str) or c["class"] not in ctx.checks:
        bad(name, "class must be a check named in the pinned verifier-check inventory")
    if c.get("sound_expected") not in ("RED", "GREEN"):
        bad(name, "sound_expected must be RED or GREEN")
    if not isinstance(c.get("manifest"), dict):
        bad(name, "manifest must be an object")
    if not (isinstance(c.get("canary"), str) and GUID_TEXT_RE.fullmatch(c["canary"])):
        bad(name, "canary must be the split's canary GUID")
    if c.get("sound_expected") == "RED" or "inventory_site" in c:
        if ctx.replay.inventory_row_for(ctx.rows, c.get("class"), c.get("inventory_site")) is None:
            bad(name, "inventory_site does not name exactly one inventory row of its class")
    if c.get("sound_expected") == "RED" and not (
            isinstance(c.get("expect_reason"), str) and c["expect_reason"].strip()):
        bad(name, "a trap must declare the refusal it earns (expect_reason)")
    authored = _when(c.get("authored_at"))
    if authored is None:
        bad(name, "authored_at must be an ISO-8601 timestamp with its offset")
    elif not ctx.pinned_at < authored <= ctx.now:
        bad(name, "authored_at is not after the pinned verifier revision and before now")
    if c.get("verifier_pin") != {"commit": ctx.pin["commit"], "verify_blob": ctx.pin["verify_blob"]}:
        bad(name, "verifier_pin must be {commit, verify_blob} of the pinned revision")
    if "neighbour" in c and not any(
            o.get("id") == c["neighbour"] and o.get("sound_expected") == "GREEN"
            for o in ctx.cases.values()):
        bad(name, "neighbour must be the id of a valid control in this set")
    if c.get("fixture") is None:
        carried = sorted(set(c) & FIXTURE_ONLY_FIELDS)
        if carried:
            bad(name, f"a static case carries {len(carried)} field(s) only a run-time fixture reads")
        src = c.get("contract_source")
        if src is not None:
            data = _pinned_file(ctx.repo, ctx.pin["commit"], src)
            if data is None:
                bad(name, "contract_source is not a file in the repository at the pin")
            elif c.get("contract_digest") and c["contract_digest"] != "sha256:" + sha256(data):
                bad(name, "contract_digest does not hash its contract_source")
    elif not isinstance(c["fixture"], str) or c["fixture"] not in ctx.vf.FIXTURES:
        bad(name, "fixture names no run-time builder of the pinned bench")


def _vet_rendering(vf, cases, bad):
    """Build each run-time fixture once and render every case on it, as the sound gate would just
    before running verify.py — which this never does."""
    with tempfile.TemporaryDirectory(prefix="vfbench-heldout-vet-") as tmp:
        built = {}
        for name, c in cases.items():
            fixture = c.get("fixture")
            if (not isinstance(fixture, str) or fixture not in vf.FIXTURES
                    or not isinstance(c.get("manifest"), dict)):
                continue
            try:
                if fixture not in built:
                    repo = Path(tmp) / fixture.replace("/", "_") / "repo"
                    built[fixture] = (repo, vf.FIXTURES[fixture](repo))
                repo, facts = built[fixture]
                holder = repo.parent / f"holder-{name}"
                holder.mkdir()
                cmd, _env = vf.fixture_command(c, facts, repo, holder)
                # The replay hands this argv to subprocess.run, which raises on a non-string: a
                # numeric unit_class or lighting must be refused here, not left unscored (PR #669).
                if not isinstance(cmd, list) or not all(isinstance(a, str) for a in cmd):
                    bad(name, "a field the fixture command carries is not a string "
                              "(unit_class, lighting or another argument)")
                    continue
                rendered = json.loads((repo / "vf-manifest.json").read_text(encoding="utf-8"))
                left = (_unrendered(rendered) + _unrendered(cmd)
                        + _unrendered(vf._render(c.get("gh_reviews"), facts)))
                if left:
                    bad(name, f"{left} {{{{placeholder}}}}(s) the fixture never fills")
                source = c.get("coordinator_contract") or facts.get("contract_source", "contract.md")
                if not (repo / source).is_file():
                    bad(name, "coordinator_contract names no contract the fixture writes")
            except Exception as exc:  # one case never stops the vet; its reason names no content
                bad(name, f"the fixture could not be built or rendered ({type(exc).__name__})")


def summarize(cases, digests, pin, files, dev_moves=None):
    """The figures a holder publishes beside the digests (#601): the set digest, the counts per
    category (the verifier check a case samples), the authoring window and the pin. Counts and
    timestamps only: no id, class name per case, field or value."""
    by_cat = {}
    for c in cases.values():
        slot = by_cat.setdefault(c["class"], {"traps": 0, "valid_controls": 0})
        slot["traps" if c["sound_expected"] == "RED" else "valid_controls"] += 1
    stamps = sorted(_when(c["authored_at"]) for c in cases.values())
    mtimes = sorted(datetime.fromtimestamp(f.stat().st_mtime, timezone.utc) for f in files)

    def iso(d):
        return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"kind": SUMMARY_KIND, "protocol": PROTOCOL_ID, "set_sha256": set_digest(digests),
            "cases": len(cases),
            "traps": sum(v["traps"] for v in by_cat.values()),
            "valid_controls": sum(v["valid_controls"] for v in by_cat.values()),
            "by_category": dict(sorted(by_cat.items())),
            "authored_from": iso(stamps[0]), "authored_to": iso(stamps[-1]),
            "file_mtime_from": iso(mtimes[0]), "file_mtime_to": iso(mtimes[-1]),
            "nearest_development_case": novelty(
                cases, development_moves() if dev_moves is None else dev_moves),
            "pinned_verifier": pin}


def load_digests(path):
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise UsageError(f"cannot read digests {path}: {exc}") from None
    hexd = re.compile(r"^[0-9a-f]{64}$")
    ok = (isinstance(doc, dict) and doc.get("kind") == DIGESTS_KIND
          and doc.get("protocol") == PROTOCOL_ID and isinstance(doc.get("cases"), list)
          and doc["cases"] and hexd.match(str(doc.get("canary_sha256") or ""))
          and all(isinstance(c, dict) and hexd.match(str(c.get("raw_sha256") or ""))
                  and hexd.match(str(c.get("canonical_sha256") or "")) for c in doc["cases"]))
    if not ok:
        raise UsageError(f"{path} is not a {DIGESTS_KIND} document for {PROTOCOL_ID}")
    return doc


# ---------------------------------------------------------------------------------------------
# check (the leakage scan)
# ---------------------------------------------------------------------------------------------

# Never fetch. A partial clone's promisor remote would otherwise be asked, object by object, for
# everything the clone never fetched: a network read in a check that must judge only what this
# repository holds. What is not here is named UNSCANNED instead (PR #645 review).
GIT_ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}


def _git(repo, *args, data=None):
    r = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True,
                       env=GIT_ENV)
    if r.returncode != 0:
        raise UsageError(f"git {' '.join(args)}: {r.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return r.stdout


def committed_blobs(repo, rev="HEAD", all_history=False):
    """[(blob sha, path)] committed at REV, or reachable from any ref with all_history."""
    if all_history:
        # --missing=print lists, as `?<sha>`, each object a partial clone never fetched (a tree
        # among them hides everything under it); they reach check as missing objects.
        listing = _git(repo, "rev-list", "--objects", "--all",
                       "--missing=print").decode("utf-8", "replace")
        pairs = [(ln.split(" ", 1)[0].lstrip("?"), ln.split(" ", 1)[1] if " " in ln else "")
                 for ln in listing.splitlines() if ln]
        kinds = _git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                     data="".join(f"{s}\n" for s, _ in pairs).encode()).decode().split("\n")
        # A missing object (a shallow or partial clone) is listed too, so check can name it
        # UNSCANNED rather than leave it out unseen (PR #645 review).
        blobs = {ln.split()[0] for ln in kinds if ln.endswith((" blob", " missing"))}
        seen, out = set(), []
        for sha, path in pairs:
            if sha in blobs and sha not in seen:
                seen.add(sha)
                out.append((sha, path))
        return out
    _git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    out = []
    for entry in _git(repo, "ls-tree", "-r", "-z", "--full-tree", rev).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        if kind == "blob":
            out.append((sha, path.decode("utf-8", "replace")))
    return out


def read_blobs(repo, shas):
    """{sha: bytes} through one `git cat-file --batch`; None for an object this repository does
    not have (`<sha> missing`, a shallow or partial clone), which crashed the parse (PR #645)."""
    if not shas:
        return {}
    raw = _git(repo, "cat-file", "--batch", data="".join(f"{s}\n" for s in shas).encode())
    out, pos = {}, 0
    for _ in shas:
        nl = raw.index(b"\n", pos)
        header = raw[pos:nl].decode().split()
        if len(header) != 3:
            out[header[0]] = None
            pos = nl + 1
            continue
        sha, _kind, size = header
        start = nl + 1
        out[sha] = raw[start:start + int(size)]
        pos = start + int(size) + 1
    return out


def _objects(node, depth=0):
    """Every object in a parsed JSON value with its depth, walked with an explicit stack: a
    recursive walk died on documents json.loads itself accepts (PR #645 review)."""
    stack = [(node, depth)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            yield node, depth
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


def decoded_text(blob):
    """The blob as text, decoded the way json.loads decodes bytes (RFC 8259 / 7159): a BOM, or the
    null-byte pattern an ASCII first character leaves, picks UTF-8, UTF-16 or UTF-32, either byte
    order (PR #645 review). None when it does not decode: binary content keeps its raw checks."""
    try:
        return blob.decode(json.detect_encoding(blob))
    except (UnicodeDecodeError, LookupError):
        return None


def scan(blob, digests):
    """The ways one blob leaks a held-out case: (kind, digest prefix). The canary and the
    canonical digest are checked on the DECODED text, so a case re-saved as UTF-16 or behind a BOM
    is still the case. Text is decoded; containers are not: a compressed, base64- or hex-encoded
    copy is outside this scan, and heldout-protocol.json states that limit beside each check."""
    raw_set = {c["raw_sha256"] for c in digests["cases"]}
    canon_set = {c["canonical_sha256"] for c in digests["cases"]}
    hits = []
    if sha256(blob) in raw_set:
        hits.append(("verbatim", sha256(blob)[:16]))
    if blob.startswith(LFS_POINTER):
        # The content lives in an LFS store this repository does not hold (PR #645 review).
        hits.append(("unscanned", "a Git LFS pointer: its content is not in this repository"))
    text = decoded_text(blob)
    guids = {g.decode("ascii").lower() for g in GUID_RE.findall(blob)}
    if text:
        guids |= {g.lower() for g in GUID_TEXT_RE.findall(text)}
        if "\\u" in text:  # a canary written with JSON escapes is still the canary
            unescaped = JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
            guids |= {g.lower() for g in GUID_TEXT_RE.findall(unescaped)}
    if any(sha256(g.encode("ascii")) == digests["canary_sha256"] for g in guids):
        hits.append(("canary", digests["canary_sha256"][:16]))
    if text is not None and JSON_START.match(text) and len(blob) > JSON_PARSE_LIMIT:
        hits.append(("unscanned", f"a {len(blob)}-byte JSON document over the {JSON_PARSE_LIMIT}-"
                                  "byte parse limit: the canonical and embedded checks did not run"))
    elif text is not None and JSON_START.match(text):
        # Depth is a reason the scan could not look, never a reason to stop the whole check: one
        # deeply nested file raised RecursionError out of the scan and ended it before any later
        # file was reported (PR #645 review). What cannot be parsed or put in canonical form is
        # named UNSCANNED; everything else in the document is still checked.
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None  # not a JSON document (JSON Lines, a prose file): a stated limit
        except RecursionError:
            doc = None
            hits.append(("unscanned", "a JSON document nested too deep to parse: the canonical "
                                      "and embedded checks did not run"))
        except ValueError as exc:
            # Valid JSON json.loads cannot convert (an integer past the int-conversion limit): a
            # case beside it was passed as clean (PR #645 review sweep).
            doc = None
            hits.append(("unscanned", f"JSON the parser cannot convert ({str(exc)[:80]}): the "
                                      "canonical and embedded checks did not run"))
        uncovered = False
        for node, depth in _objects(doc) if doc is not None else ():
            try:
                h = sha256(canonical(node))
            except (RecursionError, UnicodeEncodeError):
                # Too deep, or an unpaired surrogate UTF-8 cannot encode (`"\ud800"` is valid
                # JSON): that object is skipped, and the rest of the document is still checked.
                uncovered = True
                continue
            if h in canon_set:
                hits.append(("canonical" if depth == 0 else "embedded", h[:16]))
        if uncovered:
            hits.append(("unscanned", "objects with no canonical form (nested too deep, or an "
                                      "unpaired surrogate): the canonical and embedded checks did "
                                      "not cover them"))
    return sorted(set(hits))


def submodules(repo, rev="HEAD"):
    """[(commit, path)] of the gitlinks at REV: content another repository holds."""
    out = []
    for entry in _git(repo, "ls-tree", "-r", "-z", "--full-tree", rev).split(b"\0"):
        if entry:
            meta, path = entry.split(b"\t", 1)
            _mode, kind, sha = meta.decode().split()
            if kind == "commit":
                out.append((sha, path.decode("utf-8", "replace")))
    return out


def check(repo, digests, rev="HEAD", all_history=False):
    """(findings, blobs scanned): every committed blob that IS, or carries, a held-out case, and
    every place the scan could not look — a JSON document over the parse limit, an LFS pointer,
    a submodule at REV — as kind `unscanned`. Either kind fails the check: a scan that could not
    look is never reported clean (PR #645 review)."""
    blobs = committed_blobs(repo, rev, all_history)
    contents = read_blobs(repo, [s for s, _ in blobs])
    leaks = []
    for sha, path in blobs:
        if contents.get(sha) is None:
            leaks.append({"path": path, "blob": sha, "kind": "unscanned",
                          "digest": "an object this repository never fetched (a partial clone; "
                                    "if it is a tree, nothing under it was scanned)"})
            continue
        try:
            hits = scan(contents[sha], digests)
        except Exception as exc:  # one file never stops the check (PR #645 review)
            hits = [("unscanned", f"the scan failed on it: {type(exc).__name__}: {exc}"[:200])]
        for kind, prefix in hits:
            leaks.append({"path": path, "blob": sha, "kind": kind, "digest": prefix})
    for sha, path in submodules(repo, rev):
        leaks.append({"path": path, "blob": sha, "kind": "unscanned",
                      "digest": "a submodule: its content is another repository's"})
    if all_history:
        leaks += shallow_gap(repo)
    return leaks, len(blobs)


def shallow_gap(repo):
    """A shallow clone's history stops at its boundary commits: `rev-list --all` walks no further,
    so a case committed and deleted before them was simply never seen, and the history scan
    reported clean (PR #645 review). That unseen history is one UNSCANNED finding, which fails
    the check; the history the clone does hold is still scanned and reported. The tree at REV is
    whole in a shallow clone, so the default scan is unaffected."""
    if _git(repo, "rev-parse", "--is-shallow-repository").decode().strip() != "true":
        return []
    shallow = Path(_git(repo, "rev-parse", "--absolute-git-dir").decode().strip()) / "shallow"
    boundary = shallow.read_text(encoding="utf-8").split() if shallow.is_file() else []
    return [{"path": "(history before the shallow boundary)",
             "blob": boundary[0] if boundary else "",
             "kind": "unscanned",
             "digest": f"a shallow clone: the history before {len(boundary)} boundary commit(s) was "
                       "never fetched, so it was not scanned (git fetch --unshallow, or "
                       "actions/checkout with fetch-depth: 0)"}]


def main(argv=None):
    global JSON_PARSE_LIMIT
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_val = sub.add_parser("validate", help="the committed protocol is complete and pinned")
    p_val.add_argument("--protocol", default=str(PROTOCOL))
    p_vet = sub.add_parser("vet", help="holder side: the replay can run every case; no content shown")
    p_vet.add_argument("case_dir")
    p_vet.add_argument("--pin", required=True, help="the commit whose verify.py the set evaluates")
    p_vet.add_argument("--repo", default=str(ROOT))
    p_dig = sub.add_parser("digest", help="holder side: digests of held-out cases, never content")
    p_dig.add_argument("case_dir")
    p_dig.add_argument("--canary", required=True, help="the held-out split's canary GUID")
    p_dig.add_argument("--out", required=True)
    p_dig.add_argument("--summary", help="also vet the set and write its set digest and counts here")
    p_dig.add_argument("--pin", help="with --summary: the commit whose verify.py the set evaluates")
    p_dig.add_argument("--repo", default=str(ROOT))
    p_chk = sub.add_parser("check", help="no committed blob is or carries a held-out case")
    p_chk.add_argument("--digests", required=True)
    p_chk.add_argument("--repo", default=str(ROOT))
    p_chk.add_argument("--rev", default="HEAD")
    p_chk.add_argument("--all-history", action="store_true")
    p_chk.add_argument("--max-json-bytes", type=int, default=JSON_PARSE_LIMIT,
                       help="parse JSON documents up to this size; a larger one is UNSCANNED")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "validate":
            try:
                protocol = json.loads(Path(a.protocol).read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError) as exc:
                raise UsageError(f"cannot read {a.protocol}: {exc}") from None
            errors = validate(protocol)
            for e in errors:
                print(f"INVALID: {e}")
            if errors:
                return 1
            splits, holder = protocol["splits"], protocol["holder"]
            published = splits["heldout"].get("published_digests")
            evaluations = protocol.get("evaluations") or []
            print(f"held-out protocol {protocol['protocol']} valid: development split pinned to "
                  f"{splits['development']['corpus_sha256'][:12]}…; held-out digests "
                  f"{'published' if published else 'not yet published'}; "
                  f"holder {holder.get('assigned') or 'UNFILLED'}"
                  + (f"; {len(evaluations)} evaluation(s) bound" if evaluations else ""))
            return 0
        if a.cmd == "vet":
            pin = resolve_pin(Path(a.repo), a.pin)
            problems, cases = vet_cases(a.case_dir, pin, Path(a.repo))
            for p in problems:
                print(f"REFUSED: {p}")
            traps = sum(1 for c in cases.values() if c.get("sound_expected") == "RED")
            with pinned_bench(Path(a.repo), pin["commit"]) as bench:
                near = novelty(cases, development_moves(bench / "traps"))
            if near:
                print(f"nearest development case: {near['copies']} copies; differing leaves min "
                      f"{near['differing_leaves_min']}, median {near['differing_leaves_median']}, "
                      f"max {near['differing_leaves_max']}")
            print(f"{len(cases)} case(s) read ({traps} trap(s), {len(cases) - traps} other) against "
                  f"verify.py {pin['verify_blob'][:12]} at {pin['commit'][:12]}: "
                  + (f"{len(problems)} problem(s)" if problems else "ready to digest"))
            return 1 if problems else 0
        if a.cmd == "digest":
            if not GUID_RE.fullmatch(a.canary.encode()):
                raise UsageError("--canary is not a GUID")
            if a.summary and not a.pin:
                raise UsageError("--summary needs --pin: the counts are published with the pin")
            doc, problems = digest_cases(a.case_dir, a.canary.lower())
            cases = {}
            if a.summary:
                pin = resolve_pin(Path(a.repo), a.pin)
                vetted, cases = vet_cases(a.case_dir, pin, Path(a.repo))
                problems += vetted
            for p in problems:
                print(f"REFUSED: {p}")
            if problems:
                return 1
            Path(a.out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            print(f"{len(doc['cases'])} case digest(s) written to {a.out}; no case content included")
            if a.summary:
                with pinned_bench(Path(a.repo), pin["commit"]) as bench:
                    summary = summarize(cases, doc, pin, sorted(Path(a.case_dir).glob("*.json")),
                                        development_moves(bench / "traps"))
                Path(a.summary).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                print(f"set {summary['set_sha256']}: {summary['cases']} case(s), "
                      f"{summary['traps']} trap(s), {summary['valid_controls']} valid control(s) in "
                      f"{len(summary['by_category'])} categories; summary written to {a.summary}")
            return 0
        digests = load_digests(a.digests)
        JSON_PARSE_LIMIT = a.max_json_bytes
        findings, scanned = check(a.repo, digests, a.rev, a.all_history)
        where = "every blob reachable from any ref" if a.all_history else f"the tree at {a.rev}"
        leaks = [f for f in findings if f["kind"] != "unscanned"]
        unscanned = [f for f in findings if f["kind"] == "unscanned"]
        for leak in leaks:
            print(f"LEAK {leak['kind']}: {leak['path'] or leak['blob']} "
                  f"(blob {leak['blob'][:12]}, held-out digest {leak['digest']}…)")
        for gap in unscanned:
            print(f"UNSCANNED: {gap['path'] or gap['blob']} ({gap['blob'][:12]}): {gap['digest']}")
        if leaks:
            print(f"{len(leaks)} leak(s) in {where}: held-out content is committed beside the solver")
        if unscanned:
            print(f"{len(unscanned)} place(s) in {where} the scan could not look, so it is not "
                  "clean; each UNSCANNED line says why")
        if findings:
            return 1
        print(f"clean: {scanned} committed blob(s) in {where} checked against "
              f"{len(digests['cases'])} held-out case digest(s) and the held-out canary")
        return 0
    except UsageError as exc:
        print(f"heldout: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
