#!/usr/bin/env python3
"""Export orca-fleet missions as A2A (Agent2Agent) outcome cards (a2a-agent-card/v1).

Projects each `skills/<name>/SKILL.md` frontmatter and composition clause into a
deterministic A2A Agent Card descriptor whose input/output schemas are bound to
`runtime/evidence-manifest.md`, `runtime/scripts/guard_text.py`, and
`runtime/one-way-doors.json`.

Usage:
    python3 scripts/a2a_export.py                        # print full catalog JSON
    python3 scripts/a2a_export.py --mission ship-it      # print one mission card
    python3 scripts/a2a_export.py --out dist/a2a.json    # write to file
    python3 scripts/a2a_export.py --check                # validate all mission cards

Exit: 0 ok · 1 validation/export failure · 2 usage error.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
DOORS_PATH = ROOT / "runtime" / "one-way-doors.json"

_spec = importlib.util.spec_from_file_location("_validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate)

CARD_SCHEMA = "a2a-agent-card/v1"
CATALOG_SCHEMA = "a2a-agent-card-catalog/v1"


class ExportError(Exception):
    """Raised when a mission or governance file cannot be exported."""


def load_one_way_doors(doors_path=DOORS_PATH):
    path = Path(doors_path)
    if not path.is_file():
        raise ExportError(f"missing one-way-doors registry: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"unreadable one-way-doors registry {path}: {exc}") from exc
    doors = data.get("doors") if isinstance(data, dict) else None
    if not isinstance(doors, list) or not doors:
        raise ExportError(f"one-way-doors registry {path} has no doors list")
    ids = []
    for entry in doors:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            raise ExportError(f"malformed door entry in {path}")
        ids.append(entry["id"])
    return ids


def build_mission_card(skill_dir, door_ids=None):
    skill_dir = Path(skill_dir)
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        raise ExportError(f"missing SKILL.md in {skill_dir}")
    text, read_err = validate.read_text_safe(skill_md)
    if read_err:
        raise ExportError(f"{skill_md}: {read_err}")
    fm, err = validate.parse_frontmatter(text)
    if err or not isinstance(fm, dict):
        raise ExportError(f"{skill_md}: frontmatter error: {err}")

    name = fm.get("name")
    description = fm.get("description")
    compatibility = fm.get("compatibility", "")
    meta = fm.get("metadata")
    if not isinstance(name, str) or not name:
        raise ExportError(f"{skill_md}: missing name")
    if name != skill_dir.name:
        raise ExportError(f"{skill_md}: name {name!r} != directory {skill_dir.name!r}")
    if not isinstance(description, str) or not description:
        raise ExportError(f"{skill_md}: missing description")
    if not isinstance(meta, dict):
        raise ExportError(f"{skill_md}: missing metadata block")

    proof_tier = meta.get("proof")
    if proof_tier not in validate.PROOF_VALUES:
        raise ExportError(f"{skill_md}: invalid metadata.proof {proof_tier!r}")
    autonomy = meta.get("autonomy")
    if autonomy not in validate.AUTONOMY_VALUES:
        raise ExportError(f"{skill_md}: invalid metadata.autonomy {autonomy!r}")

    identity = {}
    for key in validate.IDENTITY_KEYS:
        val = meta.get(key)
        if not isinstance(val, str) or not val.strip():
            raise ExportError(f"{skill_md}: missing metadata.{key}")
        identity[key] = val.strip()

    if door_ids is None:
        door_ids = load_one_way_doors()

    protocols = sorted(validate.explicit_protocol_refs(text))
    if not protocols:
        raise ExportError(f"{skill_md}: no composed protocols found")

    mutating = name in validate.MUTATING_MISSIONS
    return {
        "schema": CARD_SCHEMA,
        "id": f"orca-fleet:{name}",
        "name": name,
        "description": description,
        "compatibility": compatibility,
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "autonomy": autonomy,
        "proof": {
            "tier": proof_tier,
            "evidence": meta.get("proof_evidence"),
            "mutating": mutating,
        },
        "identity": identity,
        "composition": {
            "protocols": protocols,
        },
        "contracts": {
            "input": {
                "task_spec": "markdown+json",
                "trust_envelope": "runtime/scripts/guard_text.py",
                "scope_overlap_precheck": "runtime/scripts/diff_scope.py --overlap",
                "episodic_hint": "runtime/scripts/search_sessions.py --episodic-hint",
            },
            "output": {
                "evidence_manifest": "runtime/evidence-manifest.md",
                "verifier": "runtime/scripts/verify.py" if mutating else "report-only",
                "failure_handover": "runtime/scripts/watchdog.py --handover",
            },
            "governance": {
                "gate_policy": "runtime/gate-classification.md",
                "one_way_doors_ref": "runtime/one-way-doors.json",
                "one_way_door_ids": list(door_ids),
            },
        },
    }


def build_catalog_cards(skills_dir=SKILLS_DIR, doors_path=DOORS_PATH, mission=None):
    sdir = Path(skills_dir)
    if not sdir.is_dir():
        raise ExportError(f"skills directory not found: {sdir}")
    door_ids = load_one_way_doors(doors_path)
    if mission is not None:
        target = sdir / mission
        if not target.is_dir():
            raise ExportError(f"unknown mission: {mission}")
        return build_mission_card(target, door_ids=door_ids)

    cards = []
    for entry in sorted(sdir.iterdir(), key=lambda p: p.name):
        if entry.is_dir() and (entry / "SKILL.md").is_file():
            cards.append(build_mission_card(entry, door_ids=door_ids))
    if not cards:
        raise ExportError(f"no missions found in {sdir}")
    return {
        "schema": CATALOG_SCHEMA,
        "count": len(cards),
        "cards": cards,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="a2a_export.py",
        description="Export orca-fleet missions as A2A (a2a-agent-card/v1) JSON descriptors.",
    )
    parser.add_argument("--mission", default=None, help="Export a single mission by name.")
    parser.add_argument("--skills-dir", default=str(SKILLS_DIR), help="Path to skills/ directory.")
    parser.add_argument("--doors", default=str(DOORS_PATH), help="Path to runtime/one-way-doors.json.")
    parser.add_argument("--out", default=None, help="Write JSON output to file instead of stdout.")
    parser.add_argument("--check", action="store_true", help="Validate export across all missions.")
    return parser.parse_args(argv)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    try:
        payload = build_catalog_cards(
            skills_dir=ns.skills_dir,
            doors_path=ns.doors,
            mission=ns.mission,
        )
    except ExportError as exc:
        print(f"a2a_export: FAILED: {exc}", file=sys.stderr)
        return 1

    if ns.check:
        count = 1 if ns.mission else payload["count"]
        print(f"A2A_EXPORT=ok cards={count}")
        return 0

    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if ns.out:
        out_path = Path(ns.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
