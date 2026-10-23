#!/usr/bin/env python3
"""quarantine_check.py — the fleet-wide component off-switch (#558).

Reads runtime/quarantine.json, a checked-in deny-list of components (mission,
playbook, upstream pack) a human has declared unusable. Three gates consume it:

    scripts/validate.py      the catalog may not route through a quarantined
                             component: no mission may compose a quarantined
                             playbook, pins.json may not pin a quarantined pack
                             (it builds the catalog view and imports violations()
                             from here, so the matching rule exists once)
    preflight.py --mission   a run may not start on a quarantined mission or on
                             playbooks it composes (invariant, exit 2)
    this CLI                 ad hoc checks and the tests

"Composes" means one set at all three gates (2026-10-23 review, P1-10): the
clause's backticked names and `name.md` tokens, the DEFERRED READS, every
protocol the mission body names, and every playbook those reach in turn.

Semantics, stated because they bound what this is worth: quarantine is a
checked-in file, so it takes effect on checkouts that contain it; it cannot
reach an already-running worker or a stale clone. It is the fast, reversible,
auditable rung of the response ladder (runtime/threat-model.md), not a remote
kill. Entries are HUMAN acts only — parse refuses an entry whose `by` names no
human, so an agent cannot quarantine (or, by editing, un-quarantine) anything
through the sanctioned shape.

Fail-closed, with one deliberate exception: a root with NO
runtime/quarantine.json is not a fleet catalog (preflight runs in target
repos), so there is simply no quarantine in force — the CLI says so on stderr
rather than passing silently. A PRESENT but malformed deny-list refuses every
gate: it never reads as an empty one. validate.py additionally requires the
file to exist in this repo.

Usage:
    quarantine_check.py [--root DIR] --catalog
    quarantine_check.py [--root DIR] --mission <name>
    # exit 0 = nothing quarantined is in play; 2 = violation;
    # 3 = cannot evaluate (unreadable/malformed deny-list, bad root)

Stdlib-only.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
from pathlib import Path


def _sibling(name):
    """Load a runtime/scripts sibling by path (no sys.path edits)."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The composition grammar every gate reads (COMPOSE_CLAUSE_RE used to be copied here and could
# drift from validate.py's — 2026-10-23 review, §5). validate.py loads it through this module.
_grammar = _sibling("_catalog_grammar")

KINDS = ("mission", "playbook", "pack")
_HEX = re.compile(r"^[0-9a-f]{7,40}$")
# Mirrors decisions.py's human-grant name rule verbatim (same repo, same audit
# purpose): person-shaped, and never an agent role wearing a human: prefix.
_HUMAN_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")
_RESERVED_HUMAN_NAMES = frozenset({
    "agent", "ai", "anonymous", "auto", "automatic", "bot", "coordinator",
    "fleet", "human", "model", "nobody", "none", "orca", "system",
    "unknown", "worker",
})


def parse_quarantine(data):
    """(entries, errors) from already-parsed JSON. Shape errors are loud."""
    errors = []
    if not isinstance(data, dict) or not isinstance(data.get("quarantined"), list):
        return [], ["quarantine.json: expected an object with a 'quarantined' list"]
    entries = []
    for i, raw in enumerate(data["quarantined"]):
        where = f"quarantine.json entry {i}"
        if not isinstance(raw, dict):
            errors.append(f"{where}: not an object")
            continue
        component = raw.get("component", "")
        kind, _, name = component.partition(":") if isinstance(component, str) else ("", "", "")
        if kind not in KINDS or not name or ":" in name:
            errors.append(
                f"{where}: component must be '<kind>:<name>' with kind in "
                f"{'/'.join(KINDS)} (got {component!r})"
            )
            continue
        ref = raw.get("ref", "*")
        if ref != "*" and not _HEX.fullmatch(str(ref)):
            errors.append(f"{where}: ref must be '*' or at least 7 hex chars (got {ref!r})")
            continue
        if not str(raw.get("reason", "")).strip():
            errors.append(f"{where}: reason is required — a quarantine with no reason is a rumor")
            continue
        try:
            datetime.datetime.strptime(str(raw.get("date", "")), "%Y-%m-%d")
        except ValueError:
            errors.append(f"{where}: date must be YYYY-MM-DD (got {raw.get('date')!r})")
            continue
        # Same person-shape rule as decisions.py's human grants: a bare
        # `human:` or an agent role (human:agent, human:coordinator, …) names
        # no person, and the audit trail must name one.
        by_match = re.fullmatch(r"human:(\S+)", str(raw.get("by", "")))
        by_name = by_match.group(1) if by_match else ""
        if not _HUMAN_NAME.fullmatch(by_name) or by_name.lower() in _RESERVED_HUMAN_NAMES:
            errors.append(
                f"{where}: by must be 'human:<name>' naming a person — entries are "
                "human acts, never agent-added"
            )
            continue
        entries.append(
            {"kind": kind, "name": name, "ref": str(ref),
             "reason": str(raw["reason"]), "by": str(raw["by"])}
        )
    return entries, errors


def load_quarantine(root):
    """(entries, errors, present) for <root>/runtime/quarantine.json.

    Absent (does not lexist) is the only silent state. A directory, a broken
    symlink, invalid UTF-8, or bad JSON at that path is present-but-unusable:
    an error, never an empty list.
    """
    path = Path(root) / "runtime" / "quarantine.json"
    if not os.path.lexists(path):
        return [], [], False
    if not path.is_file():
        return [], [f"{path}: present but not a regular file — refusing to "
                    "treat an unusable deny-list as an absent one"], True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        return [], [f"{path}: cannot parse ({err})"], True
    entries, errors = parse_quarantine(data)
    return entries, errors, True


def _ref_matches(ref, commit):
    if ref == "*":
        return True
    if not commit:
        return False
    return commit.startswith(ref) or ref.startswith(commit)


def violations(entries, view):
    """Quarantine violations against a catalog view.

    view = {"missions": set[str],
            "composes": {mission: set[playbook-name]},
            "pins": {pack: commit}}
    A quarantined mission still present is itself the violation a spawn gate
    refuses; the catalog gate only needs the routing checks, so callers that
    want catalog semantics pass missions=set() — see validate.py.
    """
    out = []
    for e in entries:
        label = f"{e['kind']}:{e['name']} (quarantined by {e['by']}: {e['reason']})"
        if e["kind"] == "mission" and e["name"] in view.get("missions", set()):
            out.append(f"mission {e['name']} is quarantined — {label}")
        elif e["kind"] == "playbook":
            for mission, playbooks in sorted(view.get("composes", {}).items()):
                if e["name"] in playbooks:
                    out.append(
                        f"mission {mission} composes quarantined playbook "
                        f"{e['name']} — {label}"
                    )
        elif e["kind"] == "pack":
            if view.get("pins_error"):
                out.append(
                    f"pack {e['name']} cannot be cleared — {view['pins_error']} "
                    f"— refusing rather than assuming the quarantined pack is unused"
                )
                continue
            commit = view.get("pins", {}).get(e["name"])
            if commit is not None and _ref_matches(e["ref"], commit):
                out.append(
                    f"pack {e['name']} is pinned at quarantined ref {commit} — {label}"
                )
    return out


class QuarantineError(Exception):
    """The check cannot be evaluated (missing mission, unreadable tree)."""


def _read_dependency(doc):
    try:
        return doc.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        raise QuarantineError(f"{doc}: unreadable composed dependency ({err})") from err


def _composed_playbooks(skill_text, root, skill_dir):
    """Every playbook the mission can reach, resolved BEFORE classifying the layer.

    One composition set for every gate (2026-10-23 review, P1-10 / P2-11): the clause's
    backticked names and `name.md` tokens, the DEFERRED READS, every protocol the body names,
    and — transitively — every protocol those documents name (acceptance-review → risk-review).
    The clause and the deferred reads are DECLARATIONS: missing or unreadable, they refuse,
    because a dependency nobody can read never means an unused one. Other mentions count once
    they resolve (prose is not a declaration), and an unreadable reached document refuses too.
    Catalog directories identify the layer. Bundles flatten both layers into references/, so
    every reached name conservatively keeps a quarantine edge: a document's content cannot
    exempt its own name.
    """
    references = skill_dir / "references"
    bundled = references.is_dir() or skill_dir == root
    bases = [references] if bundled else [root / "playbooks", root / "runtime"]
    listings = {}

    def candidates(name):
        return [base / f"{name}.md" for base in bases]

    def resolve(name):
        # Exact-case: on a case-insensitive filesystem `architecture` must not resolve to a
        # bundle's references/ARCHITECTURE.md.
        for path in candidates(name):
            if path.parent not in listings:
                try:
                    listings[path.parent] = set(os.listdir(path.parent))
                except OSError:
                    listings[path.parent] = set()
            if path.name in listings[path.parent]:
                return path
        return None

    declared = _grammar.clause_refs(skill_text) | _grammar.deferred_declared(skill_text)
    for name in sorted(declared):
        doc = resolve(name)
        if doc is None:
            raise QuarantineError(
                f"missing composed dependency {name}.md (tried "
                f"{', '.join(map(str, candidates(name)))}) "
                "— cannot clear the mission against the deny-list"
            )
        _read_dependency(doc)
    reached = _grammar.protocol_closure(skill_text, resolve, _read_dependency)
    return {name for name, doc in reached.items()
            if bundled or doc.parent != root / "runtime"}


def mission_view(root, mission):
    # Two root layouts: the catalog (skills/<mission>/SKILL.md) and a copied
    # single-mission bundle whose root IS the mission directory (SKILL.md and
    # references/ at the top). Refusing the second layout outright would make
    # every normal copied-bundle start fail; reading the wrong place silently
    # is the opposite error. Support both, refuse only when neither resolves.
    root = Path(root)
    candidates = [root / "skills" / mission / "SKILL.md", root / "SKILL.md"]
    skill = next((c for c in candidates if c.is_file()), None)
    if skill is None:
        raise QuarantineError(
            f"no SKILL.md for {mission} under {root} (tried "
            f"skills/{mission}/SKILL.md and ./SKILL.md) — cannot tell what it "
            "composes, so cannot clear it against the deny-list"
        )
    try:
        text = skill.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        raise QuarantineError(f"{skill}: unreadable ({err})") from err
    pins, pins_error = pins_view(root)
    return {
        "missions": {mission},
        "composes": {mission: _composed_playbooks(text, root, skill.parent)},
        "pins": pins,
        "pins_error": pins_error,
    }


def pins_view(root):
    """({pack: commit}, error-or-None) for <root>/runtime/pins.json.

    Absent pins (a target repo) is a clean empty map. Present-but-unreadable
    pins beside a pack quarantine entry must not read as "pack unused":
    the error rides the view and violations() turns it into a refusal.
    """
    path = Path(root) / "runtime" / "pins.json"
    if not os.path.lexists(path):
        return {}, None
    if not path.is_file():
        return {}, f"{path}: present but not a regular file"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        return {}, f"{path}: cannot parse ({err})"
    if not isinstance(data, dict):
        return {}, f"{path}: expected a JSON object"
    return {
        name: str(meta.get("commit", ""))
        for name, meta in data.items()
        if not name.startswith("_") and isinstance(meta, dict)
    }, None


def catalog_view(root):
    skills = Path(root) / "skills"
    missions, composes = set(), {}
    if skills.is_dir():
        for skill_dir in sorted(skills.iterdir()):
            skill = skill_dir / "SKILL.md"
            if skill_dir.is_dir() and skill.exists():
                missions.add(skill_dir.name)
                composes[skill_dir.name] = mission_view(root, skill_dir.name)["composes"][skill_dir.name]
    pins, pins_error = pins_view(root)
    return {"missions": missions, "composes": composes,
            "pins": pins, "pins_error": pins_error}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="catalog root (default: cwd)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--catalog", action="store_true", help="check the whole catalog")
    mode.add_argument("--mission", metavar="NAME", help="check one mission and its playbooks")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"quarantine_check: root {root} is not a directory", file=sys.stderr)
        return 3
    entries, errors, present = load_quarantine(root)
    if errors:
        for error in errors:
            print(f"quarantine_check: {error}", file=sys.stderr)
        return 3
    if not present:
        print(
            f"quarantine_check: no runtime/quarantine.json under {root} — "
            "no quarantine in force (not a fleet catalog?)",
            file=sys.stderr,
        )
        return 0
    if args.catalog:
        try:
            view = catalog_view(root)
        except QuarantineError as err:
            print(f"quarantine_check: {err}", file=sys.stderr)
            return 3
        present = sorted(
            e["name"] for e in entries
            if e["kind"] == "mission" and e["name"] in view["missions"]
        )
        for name in present:
            print(
                f"QUARANTINED mission {name} present in the catalog "
                "(dispatch refused at preflight; files preserved as evidence)"
            )
        view = {**view, "missions": set()}  # presence is the designed state
    else:
        try:
            view = mission_view(root, args.mission)
        except QuarantineError as err:
            print(f"quarantine_check: {err}", file=sys.stderr)
            return 3
    found = violations(entries, view)
    for violation in found:
        print(f"QUARANTINED {violation}")
    if found:
        return 2
    print("quarantine_check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
