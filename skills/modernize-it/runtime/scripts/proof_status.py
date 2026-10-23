#!/usr/bin/env python3
"""Proof-posture reporter and CI lens over the mission catalog.

Distinct from ``scripts/validate.py`` (the build gate): this tool summarizes each
mission's proof tier and surfaces whether its ``proof_evidence`` report actually
resolves to a file in the repo — for humans (default report), machines (``--json``),
and CI (``--check``).

Reads every ``skills/*/SKILL.md`` frontmatter. Never writes files, never touches the
network. Frontmatter is read by the catalog's shared reader
(``runtime/scripts/_catalog_grammar.py``, the one ``scripts/validate.py`` uses) — only
``name`` and ``metadata.proof`` / ``metadata.proof_evidence`` are consumed here.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

# runtime/scripts/proof_status.py -> repo root is three parents up.
ROOT = Path(__file__).resolve().parent.parent.parent

PROOF_TIERS = ("doctrine-only", "self-run", "external-run")
# Tiers that must carry a resolvable evidence report; doctrine-only is exempt.
TIERS_REQUIRING_EVIDENCE = {"self-run", "external-run"}


def _sibling(name):
    """Load a runtime/scripts sibling by path (no sys.path edits)."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The catalog's one frontmatter reader, shared with scripts/validate.py. This file used to carry
# a port of validate.py's copy, and the five readers had drifted (2026-10-23 review, §5).
parse_frontmatter = _sibling("_catalog_grammar").parse_frontmatter


def collect(skills_dir, root):
    """Return one record per ``skills/*/SKILL.md``, one per mission, sorted by dir name.

    Each record: name, proof, proof_evidence (str or None), evidence_resolves (bool),
    plus dir (the mission directory name) and any parse error.
    """
    records = []
    for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        md = skill_dir / "SKILL.md"
        if not md.is_file():
            continue
        rec = {
            "dir": skill_dir.name,
            "name": None,
            "proof": None,
            "proof_evidence": None,
            "evidence_resolves": False,
            "error": None,
        }
        try:
            text = md.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            rec["error"] = f"unreadable: {err}"
            records.append(rec)
            continue
        data, err = parse_frontmatter(text)
        if err:
            rec["error"] = err
            records.append(rec)
            continue
        rec["name"] = data.get("name")
        meta = data.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        # Only strings: the shared reader returns a map nested under a key as a dict.
        proof, evidence = meta.get("proof"), meta.get("proof_evidence")
        rec["proof"] = proof if isinstance(proof, str) else None
        if isinstance(evidence, str) and evidence and evidence != "<object>":
            rec["proof_evidence"] = evidence
            evidence_path = (root / evidence).resolve()
            rec["evidence_resolves"] = (
                evidence_path.is_relative_to(root.resolve()) and evidence_path.is_file()
            )
        records.append(rec)
    return records


def rollup(records):
    """Count of missions per proof tier plus total (AC-2)."""
    counts = {tier: 0 for tier in PROOF_TIERS}
    for rec in records:
        if rec["proof"] in counts:
            counts[rec["proof"]] += 1
    counts["total"] = len(records)
    return counts


def check_failures(records):
    """Missions whose tier requires evidence but whose evidence is missing/unresolvable (AC-3)."""
    failures = []
    for rec in records:
        if rec["proof"] in TIERS_REQUIRING_EVIDENCE:
            if not rec["proof_evidence"] or not rec["evidence_resolves"]:
                failures.append(rec)
    return failures


def format_report(records):
    lines = []
    name_w = max((len(r["name"] or r["dir"]) for r in records), default=4)
    tier_w = max(len(t) for t in PROOF_TIERS)
    for rec in records:
        name = rec["name"] or rec["dir"]
        tier = rec["proof"] or "?"
        evidence = rec["proof_evidence"] or "—"
        if rec["proof_evidence"]:
            mark = "ok" if rec["evidence_resolves"] else "MISSING"
        else:
            mark = "—"
        lines.append(f"{name:<{name_w}}  {tier:<{tier_w}}  [{mark:<7}] {evidence}")
    counts = rollup(records)
    lines.append("")
    lines.append("coverage rollup:")
    for tier in PROOF_TIERS:
        lines.append(f"  {tier:<{tier_w}}  {counts[tier]}")
    lines.append(f"  {'total':<{tier_w}}  {counts['total']}")
    return "\n".join(lines)


def json_records(records):
    """Per-mission machine-readable array (AC-3, --json)."""
    return [
        {
            "name": rec["name"],
            "proof": rec["proof"],
            "proof_evidence": rec["proof_evidence"],
            "evidence_resolves": rec["evidence_resolves"],
        }
        for rec in records
    ]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Proof-posture reporter and CI lens over the mission catalog."
    )
    ap.add_argument("--json", action="store_true", help="emit per-mission records as a JSON array")
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero iff a mission above doctrine-only lacks resolvable proof_evidence",
    )
    ap.add_argument("--root", default=None, help="repo root (default: inferred from this script)")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else ROOT
    skills_dir = root / "skills"
    if not skills_dir.is_dir():
        print(f"no skills/ directory under {root}", file=sys.stderr)
        return 1

    records = collect(skills_dir, root)

    if args.json:
        print(json.dumps(json_records(records), indent=2))
    else:
        print(format_report(records))

    if args.check:
        failures = check_failures(records)
        if failures:
            for rec in failures:
                name = rec["name"] or rec["dir"]
                why = "no proof_evidence" if not rec["proof_evidence"] else "unresolvable proof_evidence"
                print(
                    f"FAIL: {name} ({rec['proof']}) — {why}: {rec['proof_evidence'] or '—'}",
                    file=sys.stderr,
                )
            print(
                f"proof-status: {len(failures)} mission(s) above doctrine-only missing evidence",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
