#!/usr/bin/env python3
"""certification.py — validate and render the provider/harness certification record (#596).

`runtime/providers/certification.json` maps every ADVERTISED route to the strongest evidence
that exists for it, so "supported" can never again mean only "an adapter exists":

  provider cells  every (provider, profile, harness) in capabilities.json's
                  supported_profiles x supported_harnesses — the matrix docs/runtimes.md
                  advertises;
  harness cells   every (harness, profile) of the shared launch table
                  (runtime/providers/base.py build_harness_command), ro and rw.

A cell carries a tier, the exact upstream version or commit it was certified against (null is
rendered `unknown` and is never guessed), evidence paths, and explicit limitations. Tiers:

  live-witnessed  a real upstream build and a real harness ran the route; bound run report.
  fixture-tested  the fleet's code for the route runs in CI against an in-repo fixture (a
                  scripted upstream transport or an inert worker): proves our side only.
  source-only     the launch was written from upstream source or docs; nothing drives it.
  unsupported     the fleet refuses the route before any launch, with a typed refusal.
  unavailable     advertised, but no evidence of any kind exists here: state unknown.

Checks (`check`, the default) — each failure is one `FAIL:` line:
  1. shape: schema_version, record_version, exactly the five tiers, known keys only;
  2. coverage: each provider's route groups partition its advertised matrix exactly (a cell
     missing, doubled or not advertised fails), and the harness groups partition
     SUPPORTED_HARNESSES x {ro, rw};
  3. evidence: every path resolves under --root; `path::Name` must define `class Name` or
     `def Name` there; every group states at least one limitation;
  4. live-witnessed: needs `witnessed` (upstream_version, harness_version, host, date, route), an
     exact upstream version, and a docs/runs/*.md report whose RUN: header records verifier=GREEN
     at a self-run/external-run tier and which BINDS under run_report.py's check_report — the check
     scripts/validate.py applies to proof_evidence (it re-hashes the inventory at the pinned
     commit, so it needs full git history, like validate.py). `route` quotes whole lines of that
     run's inventoried artifacts, read at its inventory_at, which must NAME every cell of the
     group: provider, PROFILE=<p> beside the harness, and the recorded versions. Quotes of an
     inert first run (its `witness` line says worker=inert / tier=fixture-tested) certify
     nothing, and a harness cell needs a provider other than orca named (base.py's table runs
     off Orca; Orca launches spawn_worker.sh's own rows). The fields a maintainer copies from a
     first_run.py receipt are checked too: a harness cell's upstream.version is named in
     witnessed.harness_version, an in-repo provider's upstream_version is a commit on HEAD's
     history (the receipt's catalog commit), and witnessed.date is YYYY-MM-DD;
  5. unsupported: needs the typed `refusal` code the route is refused with;
  6. freshness: a provider bound to a pin (`upstream.pin` = `<file>#<key>`) is STALE once the
     pin's commit, version or live_receipts.version differs from `certified_against`. Every
     cell of that provider then reads `stale` — never its recorded tier — and the check fails
     until a maintainer rechecks the cells and re-records `certified_against`.

Usage:
  certification.py [check]  [--root DIR] [--record FILE] [--pins FILE]
  certification.py matrix   [--json] [--root DIR] [--record FILE] [--pins FILE]
  certification.py markdown [--root DIR] [--record FILE] [--pins FILE]
`--pins` previews a re-pin: point it at the candidate pins file to list the cells it voids.

Exit: 0 valid and fresh · 1 invalid or stale (matrix/markdown still print) · 2 unreadable / usage.
"""
from __future__ import annotations

import argparse
import datetime
import functools
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCHEMA = "open-fleet-certification/v1"
TIERS = ("live-witnessed", "fixture-tested", "source-only", "unsupported", "unavailable")
HARNESS_PROFILES = ("ro", "rw")
GROUP_KEYS = {"profiles", "harnesses", "tier", "evidence", "limitations", "refusal", "witnessed"}
WITNESS_KEYS = ("upstream_version", "harness_version", "host", "date")
# How run evidence names a harness or provider beyond its bare key. Harness words match without
# case; provider words with it, so `Orca` (the runtime) never matches `orca-fleet` (this repo).
HARNESS_WORDS = {"claude": ("claude", "claude code"), "omp": ("omp", "oh-my-pi"), "antigravity": ("antigravity", "agy"),
                 "cursor": ("cursor", "cursor-agent")}
PROVIDER_WORDS = {"orca": ("orca-ide", "Orca")}
PROFILE_RE = r"""\bPROFILE=["']?{profile}\b"""
# A first_run.py receipt says what kind of worker ran (its `witness` line): a stand-in proves the
# fleet's route only, so evidence that quotes one certifies nothing live (#596).
FIXTURE_MARKS = ("worker=inert", "tier=fixture-tested")
# An upstream that is this repository: its witness is the catalog commit the run ran (#596).
IN_REPO = "in-repo"
SYMBOL_RE = r"(?m)^\s*(?:class|def|async def)\s+{name}\b"


@functools.lru_cache(maxsize=None)
def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@functools.lru_cache(maxsize=None)
def _binds(rel: str, mission: str, tier: str, root: Path) -> bool:
    """run_report.check_report is a git re-hash of the whole inventory: pay it once per process."""
    run_report = _load_module("of_cert_run_report", ROOT / "runtime" / "scripts" / "run_report.py")
    return not run_report.check_report(rel, mission, tier, root)


def base_harnesses() -> tuple[str, ...]:
    """The launch table's harnesses, read from base.py itself (one source of truth)."""
    return tuple(_load_module("of_cert_base", ROOT / "runtime" / "providers" / "base.py").SUPPORTED_HARNESSES)


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def pin_entry(ref: str, root: Path, pins_override: Path | None) -> tuple[dict | None, str]:
    """(entry, error) for an `upstream.pin` reference `<file>#<key>`."""
    file_part, _, key = ref.partition("#")
    if not file_part or not key:
        return None, f"pin reference {ref!r} is not <file>#<key>"
    path = pins_override or (root / file_part)
    try:
        entry = read_json(path).get(key)
    except (OSError, ValueError) as exc:
        return None, f"pin {ref!r} unreadable: {exc}"
    if not isinstance(entry, dict):
        return None, f"pin {ref!r} names no entry"
    return entry, ""


def pin_fingerprint(entry: dict) -> dict:
    """The three facts a certification is bound to: what is pinned, and what was run live."""
    return {
        "commit": entry.get("commit"),
        "version": entry.get("version"),
        "live_receipts_version": (entry.get("live_receipts") or {}).get("version"),
    }


def _evidence_errors(where: str, evidence, root: Path) -> list[str]:
    errors = []
    if not isinstance(evidence, list) or not evidence:
        return [f"{where}: evidence must be a non-empty list of paths"]
    for item in evidence:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}: evidence entry {item!r} is not a path")
            continue
        rel, _, name = item.partition("::")
        path = root / rel
        if rel.startswith("/") or ".." in Path(rel).parts or not path.is_file():
            errors.append(f"{where}: evidence {rel!r} does not exist under the repository root")
            continue
        if name and not re.search(SYMBOL_RE.format(name=re.escape(name)), path.read_text(encoding="utf-8")):
            errors.append(f"{where}: evidence {item!r} — {rel} defines no class/def {name}")
    return errors


@functools.lru_cache(maxsize=None)
def _bound_artifacts(report_rel: str, root: Path) -> dict:
    """{path: stripped lines} for every artifact in the run's OWN directory that the report's
    inventory binds, read from git at its inventory_at — the run's evidence, not the tree's."""
    run_report = _load_module("of_cert_run_report", ROOT / "runtime" / "scripts" / "run_report.py")
    report = root / report_rel
    fields, err = run_report.parse_run_header(report.read_text(encoding="utf-8"))
    run_dir = None if err else run_report.run_directory(report, fields["mission"], root)
    if run_dir is None:
        return {}
    try:
        _report, _lines, entries = run_report.inventory.load(report)
    except run_report.inventory.InventoryError:
        return {}
    matched, _mismatched, _missing = run_report.inventory.check_entries(entries, report, root, at=fields["inventory_at"])
    out = {}
    for path in matched:
        blob = run_report.blob_at(fields["inventory_at"], path, root) if path.startswith(run_dir + "/") else None
        if blob is not None:
            out[path] = tuple(ln.strip() for ln in blob.decode("utf-8", "replace").splitlines())
    return out


def _names(text: str, words: tuple[str, ...], *, case: bool = False) -> bool:
    flags = 0 if case else re.IGNORECASE
    return any(re.search(rf"(?<![\w-]){re.escape(w)}(?![\w-])", text, flags) for w in words)


def _route_errors(where: str, cells: list[tuple[str, str, str, str]], witnessed: dict, bound: list[str],
                  root: Path, providers: tuple[str, ...] = ()) -> list[str]:
    """A live cell is live only for the route its bound evidence NAMES (#596 review): a group
    that copied another route's witness and cited its run must not certify a harness, profile
    or provider that run never dispatched. The record only points (`route`: path + whole lines);
    the route itself is read from those lines as the cited run's inventory binds them."""
    quotes = witnessed.get("route")
    if not isinstance(quotes, list) or not quotes:
        return [f"{where}: live-witnessed needs `witnessed.route`: whole lines of the cited run's bound "
                "artifacts that name the route's provider, profile and harness; evidence that names no "
                "route certifies none"]
    errors, texts = [], []
    artifacts: dict = {}
    for rel in bound:
        artifacts.update(_bound_artifacts(rel, root))
    for quote in quotes:
        path = quote.get("path") if isinstance(quote, dict) else None
        lines = quote.get("lines") if isinstance(quote, dict) else None
        if not isinstance(path, str) or not isinstance(lines, list) or not lines \
                or not all(isinstance(x, str) and x.strip() for x in lines):
            errors.append(f"{where}: witnessed.route entry {quote!r} needs a `path` and non-empty `lines`")
            continue
        if path not in artifacts:
            errors.append(f"{where}: witnessed.route {path} is not an artifact the cited run's inventory binds "
                          "(it must be listed in that report's inventory, inside the run's own directory)")
            continue
        have, want = artifacts[path], tuple(x.strip() for x in lines)
        if not any(have[i:i + len(want)] == want for i in range(len(have) - len(want) + 1)):
            errors.append(f"{where}: witnessed.route {path} does not carry the quoted lines at the run's inventory_at")
            continue
        texts.append("\n".join(want))
    if errors:
        return errors
    fixture = sorted({m for m in FIXTURE_MARKS for t in texts if m in t})
    if fixture:
        return [f"{where}: the quoted evidence is a fixture run ({', '.join(fixture)}): an inert stand-in "
                "proves the fleet's route, never a live one"]
    # base.py's launch table runs off Orca only; Orca launches spawn_worker.sh's own rows (#596).
    off_orca = [p for p in providers if p != "orca"]
    for kind, name, profile, harness in cells:
        words = HARNESS_WORDS.get(harness, (harness,))
        missing = []
        if kind == "provider" and not any(_names(t, PROVIDER_WORDS.get(name, (name,)), case=True) for t in texts):
            missing.append(f"provider {name}")
        if kind == "harness" and not any(_names(t, PROVIDER_WORDS.get(p, (p,)), case=True)
                                         for t in texts for p in off_orca):
            missing.append("provider that launches base.py's line: the harness table runs off Orca only, and "
                           "the Orca route launches spawn_worker.sh's own rows")
        if not any(re.search(PROFILE_RE.format(profile=re.escape(profile)), t) and _names(t, words) for t in texts):
            missing.append(f"PROFILE={profile} beside harness {harness} in one quote")
        hv, uv = witnessed.get("harness_version"), witnessed.get("upstream_version")
        if hv and not (_names(hv, words) and any(hv in t for t in texts)):
            missing.append(f"harness version {hv!r} naming {harness}")
        if uv and not any(uv in t for t in texts):
            missing.append(f"upstream version {uv!r}")
        if missing:
            errors.append(f"{where}: live-witnessed {profile}/{harness}: the cited evidence does not identify this "
                          f"route — no {'; no '.join(missing)} in witnessed.route")
    return errors


def _live_errors(where: str, group: dict, root: Path, run_report, cells=(), providers=()) -> list[str]:
    errors = []
    witnessed = group.get("witnessed")
    if not isinstance(witnessed, dict) or any(not witnessed.get(k) for k in WITNESS_KEYS):
        errors.append(f"{where}: live-witnessed needs `witnessed` with {', '.join(WITNESS_KEYS)}")
    reports = [e for e in group.get("evidence") or [] if isinstance(e, str)
               and e.startswith("docs/runs/") and e.endswith(".md") and "::" not in e]
    bound = []
    for rel in reports:
        path = root / rel
        if not path.is_file():
            continue
        fields, err = run_report.parse_run_header(path.read_text(encoding="utf-8"))
        if err or fields.get("verifier") != "GREEN" or fields.get("tier") not in run_report.ADVANCING_TIERS:
            continue
        if _binds(rel, fields["mission"], fields["tier"], root):
            bound.append(rel)
    if not bound:
        errors.append(f"{where}: live-witnessed without a binding run report — cite a docs/runs/*.md whose RUN: "
                      "header records verifier=GREEN and which binds under run_report.py")
    elif isinstance(witnessed, dict):
        errors += _route_errors(where, list(cells), witnessed, bound, root, tuple(providers))
    return errors


def _witness_field_errors(where: str, kind: str, upstream: dict, witnessed, root: Path, run_report) -> list[str]:
    """The fields a maintainer copies from the run's receipt agree with the witness (#596).

    A harness cell's own `upstream.version` is the version the run reported (receipt
    facts.harness.version, quoted as witnessed.harness_version); an in-repo provider is witnessed
    at the catalog commit the run ran (receipt host.catalog_commit), which must be in this
    repository's history; and the date is a calendar date.
    """
    if not isinstance(witnessed, dict):
        return []
    errors = []
    date = str(witnessed.get("date") or "")
    try:
        datetime.date.fromisoformat(date)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError(date)
    except ValueError:
        if date:
            errors.append(f"{where}: witnessed.date {date!r} is not a calendar date (YYYY-MM-DD)")
    hv = str(witnessed.get("harness_version") or "")
    version = upstream.get("version")
    if kind == "harness" and version and str(version) not in hv:
        errors.append(f"{where}: upstream.version {version!r} is not the witnessed harness version {hv!r}: copy "
                      "it from the run receipt's facts.harness.version")
    uv = str(witnessed.get("upstream_version") or "")
    if kind == "provider" and version == IN_REPO and not (
            re.fullmatch(r"[0-9a-f]{40}", uv) and run_report.is_ancestor(uv, "HEAD", root)):
        errors.append(f"{where}: an in-repo provider is witnessed at a commit of this repository: upstream_version "
                      f"{uv!r} must be the run receipt's host.catalog_commit, an ancestor of HEAD")
    return errors


def expand(record: dict, caps: dict, harnesses: tuple[str, ...]) -> tuple[list[dict], list[str]]:
    """Every certification cell, and the coverage/shape errors found building them."""
    cells: list[dict] = []
    errors: list[str] = []
    advertised = caps.get("providers") or {}
    recorded = record.get("providers") or {}
    for name in sorted(set(advertised) - set(recorded)):
        errors.append(f"provider {name}: advertised in capabilities.json but not certified")
    for name in sorted(set(recorded) - set(advertised)):
        errors.append(f"provider {name}: certified but not advertised in capabilities.json")
    for name in sorted(set(advertised) & set(recorded)):
        want = {(p, h) for p in advertised[name].get("supported_profiles") or []
                for h in advertised[name].get("supported_harnesses") or []}
        entry = recorded[name]
        cells += _expand_groups(f"provider {name}", "provider", name, entry.get("routes"), want, entry, errors)
    recorded_h = record.get("harnesses") or {}
    for name in sorted(set(harnesses) - set(recorded_h)):
        errors.append(f"harness {name}: in base.py SUPPORTED_HARNESSES but not certified")
    for name in sorted(set(recorded_h) - set(harnesses)):
        errors.append(f"harness {name}: certified but not in base.py SUPPORTED_HARNESSES")
    for name in sorted(set(harnesses) & set(recorded_h)):
        want = {(p, name) for p in HARNESS_PROFILES}
        entry = recorded_h[name]
        cells += _expand_groups(f"harness {name}", "harness", name, entry.get("routes"), want, entry, errors)
    return cells, errors


def _expand_groups(where, kind, name, groups, want, entry, errors) -> list[dict]:
    cells = []
    if not isinstance(groups, list) or not groups:
        errors.append(f"{where}: routes must be a non-empty list")
        return cells
    seen: dict[tuple[str, str], int] = {}
    for i, group in enumerate(groups):
        gwhere = f"{where} route[{i}]"
        if not isinstance(group, dict):
            errors.append(f"{gwhere}: not an object")
            continue
        unknown = set(group) - GROUP_KEYS
        if unknown:
            errors.append(f"{gwhere}: unknown keys {sorted(unknown)}")
        profiles = group.get("profiles") or []
        hs = [name] if kind == "harness" else (group.get("harnesses") or [])
        if kind == "harness" and "harnesses" in group:
            errors.append(f"{gwhere}: a harness route names profiles only")
        for p in profiles:
            for h in hs:
                key = (p, h)
                if key in seen:
                    errors.append(f"{gwhere}: {p}/{h} already classified by route[{seen[key]}]")
                    continue
                seen[key] = i
                if key not in want:
                    errors.append(f"{gwhere}: {p}/{h} is not an advertised {kind} route")
                    continue
                cells.append({
                    "kind": kind, "name": name, "profile": p, "harness": h, "group": i,
                    "tier": group.get("tier"), "evidence": group.get("evidence"),
                    "limitations": group.get("limitations"), "refusal": group.get("refusal"),
                    "witnessed": group.get("witnessed"), "upstream": entry.get("upstream") or {},
                })
    for p, h in sorted(want - set(seen)):
        errors.append(f"{where}: advertised route {p}/{h} is not classified")
    return cells


def validate(root: Path, record_path: Path | None = None, pins_path: Path | None = None) -> tuple[list[str], list[str], list[dict]]:
    """(errors, stale_notes, cells). Errors include staleness; notes say what to recheck."""
    record = read_json(record_path or root / "runtime" / "providers" / "certification.json")
    caps = read_json(root / "runtime" / "providers" / "capabilities.json")
    run_report = _load_module("of_cert_run_report", ROOT / "runtime" / "scripts" / "run_report.py")
    errors: list[str] = []
    if record.get("schema_version") != SCHEMA:
        errors.append(f"schema_version must be {SCHEMA!r}")
    if not isinstance(record.get("record_version"), int) or record.get("record_version") < 1:
        errors.append("record_version must be a positive integer (bump it with every re-certification)")
    if set(record.get("tiers") or {}) != set(TIERS):
        errors.append(f"tiers must define exactly {', '.join(TIERS)}")
    cells, cover = expand(record, caps, base_harnesses())
    errors += cover
    checked: set[tuple[str, str, int]] = set()
    for cell in cells:
        gkey = (cell["kind"], cell["name"], cell["group"])
        if gkey in checked:
            continue
        checked.add(gkey)
        where = f"{cell['kind']} {cell['name']} route[{cell['group']}]"
        if cell["tier"] not in TIERS:
            errors.append(f"{where}: tier {cell['tier']!r} is not one of {', '.join(TIERS)}")
            continue
        errors += _evidence_errors(where, cell["evidence"], root)
        lims = cell["limitations"]
        if not isinstance(lims, list) or not lims or not all(isinstance(x, str) and x.strip() for x in lims):
            errors.append(f"{where}: limitations must be a non-empty list of statements")
        if cell["tier"] == "live-witnessed":
            group = {"witnessed": cell["witnessed"], "evidence": cell["evidence"]}
            route = [(c["kind"], c["name"], c["profile"], c["harness"]) for c in cells
                     if (c["kind"], c["name"], c["group"]) == gkey]
            errors += _live_errors(where, group, root, run_report, route, tuple(caps.get("providers") or {}))
            if not (cell["upstream"].get("version") or cell["upstream"].get("commit")):
                errors.append(f"{where}: live-witnessed on an upstream whose version is unknown")
            errors += _witness_field_errors(where, cell["kind"], cell["upstream"], cell["witnessed"], root, run_report)
        elif cell["witnessed"] is not None:
            errors.append(f"{where}: only a live-witnessed route carries `witnessed`")
        if cell["tier"] == "unsupported" and not (isinstance(cell["refusal"], str) and cell["refusal"]):
            errors.append(f"{where}: unsupported needs the typed `refusal` code the route is refused with")
    stale: list[str] = []
    for name, entry in sorted((record.get("providers") or {}).items()):
        ref = (entry.get("upstream") or {}).get("pin")
        if not ref:
            continue
        pin, err = pin_entry(ref, root, pins_path)
        if err:
            errors.append(f"provider {name}: {err}")
            continue
        now, then = pin_fingerprint(pin), entry.get("certified_against")
        if now != then:
            stale.append(f"provider {name}: certified against {then}, but {ref} is now {now} — "
                         f"recheck its cells, then re-record certified_against")
            for cell in cells:
                if cell["kind"] == "provider" and cell["name"] == name:
                    cell["stale"] = True
    errors += [f"STALE {s}" for s in stale]
    for cell in cells:
        cell["effective"] = "stale" if cell.get("stale") else cell["tier"]
    return errors, stale, cells


def version_label(upstream: dict) -> str:
    version, commit = upstream.get("version"), upstream.get("commit")
    if version and commit:
        return f"{version} ({commit[:12]})"
    return version or (commit[:12] if commit else "unknown")


def render_markdown(cells: list[dict], record: dict) -> str:
    """The generated block docs/certification.md carries (its freshness is a test)."""
    tiers = TIERS + ("stale",)
    out = [f"Record version {record.get('record_version')} ({record.get('recorded')}). "
           "Counts are cells: one (provider, profile, harness) or (harness, profile) route each.", ""]
    out += ["| Provider | Upstream certified against | " + " | ".join(tiers) + " |",
            "|---|---|" + "---|" * len(tiers)]
    for name in sorted({c["name"] for c in cells if c["kind"] == "provider"}):
        mine = [c for c in cells if c["kind"] == "provider" and c["name"] == name]
        counts = [str(sum(c["effective"] == t for c in mine) or "") for t in tiers]
        out.append(f"| `{name}` | {version_label(mine[0]['upstream'])} | " + " | ".join(counts) + " |")
    out += ["", "| Harness | Upstream version | " + " | ".join(t for t in tiers if t != "stale") + " |",
            "|---|---|" + "---|" * (len(tiers) - 1)]
    for name in sorted({c["name"] for c in cells if c["kind"] == "harness"}):
        mine = [c for c in cells if c["kind"] == "harness" and c["name"] == name]
        counts = [str(sum(c["effective"] == t for c in mine) or "") for t in tiers if t != "stale"]
        out.append(f"| `{name}` | {version_label(mine[0]['upstream'])} | " + " | ".join(counts) + " |")
    live = [c for c in cells if c["effective"] == "live-witnessed"]
    out += ["", "Live-witnessed cells (everything else is fixture, source or refusal evidence):", ""]
    for c in live:
        w = c["witnessed"] or {}
        out.append(f"- `{c['name']}` {c['profile']}/{c['harness']}: upstream {w.get('upstream_version')}, "
                   f"{w.get('harness_version')}, {w.get('host')}, {w.get('date')} — "
                   + ", ".join(f"[{Path(e).name}]({e[len('docs/'):]})" for e in c["evidence"] if e.startswith("docs/runs/")))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="certification.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", nargs="?", default="check", choices=("check", "matrix", "markdown"))
    ap.add_argument("--root", default=str(ROOT), help="repository root evidence paths resolve under")
    ap.add_argument("--record", default=None, help="certification record (default runtime/providers/certification.json)")
    ap.add_argument("--pins", default=None, help="pins file to compare against (default each pin's own file)")
    ap.add_argument("--json", action="store_true", help="matrix: print JSON cells")
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.root).resolve()
    try:
        errors, _stale, cells = validate(root, Path(args.record) if args.record else None,
                                         Path(args.pins) if args.pins else None)
        record = read_json(Path(args.record) if args.record else root / "runtime" / "providers" / "certification.json")
    except (OSError, ValueError) as exc:
        print(f"certification: cannot read the record: {exc}", file=sys.stderr)
        return 2
    if args.mode == "matrix":
        rows = [{k: c[k] for k in ("kind", "name", "profile", "harness", "tier", "effective", "refusal")}
                | {"upstream": version_label(c["upstream"])} for c in cells]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"{r['kind']}\t{r['name']}\t{r['profile']}/{r['harness']}\t{r['effective']}\t{r['upstream']}")
    elif args.mode == "markdown":
        print(render_markdown(cells, record), end="")
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    if args.mode == "check" and not errors:
        by = {t: sum(c["effective"] == t for c in cells) for t in TIERS}
        print(f"certification: OK — {len(cells)} cells, fresh against their pins ("
              + ", ".join(f"{n} {t}" for t, n in by.items() if n) + ")")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
