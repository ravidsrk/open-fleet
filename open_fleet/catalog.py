"""Catalog discovery, mission metadata, certification reading, and intent routing."""

import importlib.util
import json
import math
import re
from pathlib import Path
from typing import Any

from open_fleet import catalog_version, find_catalog_root

MISSION_CATEGORIES: dict[str, str] = {
    "map-it": "Plan, Build & Ship",
    "ship-it": "Plan, Build & Ship",
    "oss-contribute": "Plan, Build & Ship",
    "absorb-it": "Plan, Build & Ship",
    "clean-sweep": "Fix, Sweep & Stabilize",
    "deflake-it": "Fix, Sweep & Stabilize",
    "field-test-it": "Fix, Sweep & Stabilize",
    "review-it": "Review, Diagnose & Prove",
    "root-cause": "Review, Diagnose & Prove",
    "prove-it": "Review, Diagnose & Prove",
    "floor-it": "Review, Diagnose & Prove",
    "harden-it": "Audit, Harden & Attest",
    "attest-it": "Audit, Harden & Attest",
    "access-it": "Audit, Harden & Attest",
    "speed-it": "Audit, Harden & Attest",
    "modernize-it": "Evolve, Refactor & Migrate",
    "reshape-it": "Evolve, Refactor & Migrate",
    "migrate-it": "Evolve, Refactor & Migrate",
    "oncall-it": "Operate, Document & Provision",
    "document-it": "Operate, Document & Provision",
    "offload-it": "Operate, Document & Provision",
    "pin-it": "Operate, Document & Provision",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for", "from",
    "get", "have", "how", "i", "if", "in", "into", "is", "it", "its", "me", "my",
    "need", "of", "on", "or", "our", "out", "please", "run", "should", "so", "that",
    "the", "their", "them", "there", "these", "this", "to", "up", "us", "use",
    "want", "we", "what", "when", "where", "which", "with", "would", "you", "your",
})

_GRAMMAR_CACHE: dict[Path, Any] = {}


def _load_grammar(root: Path) -> Any:
    resolved = root.resolve()
    cached = _GRAMMAR_CACHE.get(resolved)
    if cached is not None:
        return cached
    path = resolved / "runtime" / "scripts" / "_catalog_grammar.py"
    spec = importlib.util.spec_from_file_location("_open_fleet_catalog_grammar", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load catalog grammar from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _GRAMMAR_CACHE[resolved] = mod
    return mod


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _stem(word: str) -> str:
    w = word.lower()
    if len(w) <= 3:
        return w
    for suffix in ("ation", "ition", "ment", "ness", "ings", "ing", "ied", "ies", "ed", "es", "ly", "er", "s"):
        if w.endswith(suffix) and len(w) - len(suffix) >= 3:
            if suffix in ("ies", "ied"):
                return w[: -len(suffix)] + "y"
            return w[: -len(suffix)]
    return w


def _tokenize(text: str, synonyms: dict[str, list[str]] | None = None) -> list[str]:
    raw = _TOKEN_RE.findall(text.lower())
    out: list[str] = []
    for tok in raw:
        if tok in _STOPWORDS:
            continue
        out.append(_stem(tok))
        if synonyms and tok in synonyms:
            for alias in synonyms[tok]:
                for part in _TOKEN_RE.findall(alias.lower()):
                    if part not in _STOPWORDS:
                        out.append(_stem(part))
    return out


def _split_description(desc: str) -> tuple[str, str, str]:
    """Split description into (main, use_when, not_for) segments."""
    not_match = re.search(r"\bNot\s+for\b.*", desc, re.IGNORECASE | re.DOTALL)
    not_for = not_match.group(0) if not_match else ""
    before_not = desc[: not_match.start()] if not_match else desc
    use_match = re.search(r"\bUse\s+when\b.*", before_not, re.IGNORECASE | re.DOTALL)
    use_when = use_match.group(0) if use_match else ""
    main = before_not[: use_match.start()] if use_match else before_not
    return main.strip(), use_when.strip(), not_for.strip()


def _extract_section(body: str, heading: str) -> str:
    pattern = re.compile(rf"(?ms)^##\s+{re.escape(heading)}\b.*?\n(.*?)(?=^##\s+|\Z)")
    match = pattern.search(body)
    return match.group(1).strip() if match else ""


def _split_body(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                return "\n".join(lines[idx + 1 :]).strip()
    return text.strip()


def load_capabilities(root: Path | None = None) -> dict[str, Any]:
    base = root or find_catalog_root()
    data = _read_json(base / "runtime" / "providers" / "capabilities.json", {})
    return data if isinstance(data, dict) else {}


def load_certification(root: Path | None = None) -> dict[str, Any]:
    base = root or find_catalog_root()
    data = _read_json(base / "runtime" / "providers" / "certification.json", {})
    return data if isinstance(data, dict) else {}


def load_pins(root: Path | None = None) -> dict[str, Any]:
    base = root or find_catalog_root()
    data = _read_json(base / "runtime" / "pins.json", {})
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_quarantine(root: Path | None = None) -> dict[str, Any]:
    base = root or find_catalog_root()
    path = base / "runtime" / "quarantine.json"
    data = _read_json(path, None)
    if not isinstance(data, dict) or not isinstance(data.get("quarantined"), list):
        return {"valid": False, "quarantined": [], "error": f"unreadable or malformed {path}"}
    return {"valid": True, "quarantined": list(data["quarantined"]), "error": None}


def load_one_way_doors(root: Path | None = None) -> list[dict[str, Any]]:
    base = root or find_catalog_root()
    data = _read_json(base / "runtime" / "one-way-doors.json", {})
    doors = data.get("doors") if isinstance(data, dict) else None
    return doors if isinstance(doors, list) else []


def load_budgets(root: Path | None = None) -> dict[str, int]:
    base = root or find_catalog_root()
    data = _read_json(base / "scripts" / "mission-load-budgets.json", {})
    budgets = data.get("budgets") if isinstance(data, dict) else None
    if not isinstance(budgets, dict):
        return {}
    return {str(k): int(v) for k, v in budgets.items() if isinstance(v, (int, float))}


def load_retained_runs(root: Path | None = None) -> list[dict[str, Any]]:
    base = root or find_catalog_root()
    index_dir = base / "docs" / "runs" / "index"
    if not index_dir.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(index_dir.glob("*.json"), reverse=True):
        row = _read_json(path, None)
        if not isinstance(row, dict):
            continue
        mission_raw = str(row.get("mission") or "")
        match = re.match(r"\[([^\]]+)\]\(([^)]+)\)", mission_raw)
        mission_name = match.group(1) if match else mission_raw
        rows.append({
            "id": path.stem,
            "date": str(row.get("date") or ""),
            "report": str(row.get("report") or ""),
            "mission": mission_name,
            "mission_raw": mission_raw,
            "target": str(row.get("target") or ""),
            "ran_as": str(row.get("ran_as") or ""),
            "binds": str(row.get("binds") or ""),
            "binds_yes": str(row.get("binds") or "").strip().lower().startswith("yes"),
            "outcome": str(row.get("outcome") or ""),
        })
    return rows


def list_missions(
    root: Path | None = None,
    *,
    proof: str | None = None,
    category: str | None = None,
    include_body: bool = False,
) -> list[dict[str, Any]]:
    """Return structured metadata for all discoverable missions under skills/."""
    base = root or find_catalog_root()
    grammar = _load_grammar(base)
    caps = load_capabilities(base).get("missions", {})
    budgets = load_budgets(base)
    skills_dir = base / "skills"
    if not skills_dir.is_dir():
        return []

    missions: list[dict[str, Any]] = []
    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith((".", "_")):
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        text = skill_md.read_text(encoding="utf-8")
        fm, err = grammar.parse_frontmatter(text)
        if err or not isinstance(fm, dict):
            continue
        name = str(fm.get("name") or skill_dir.name)
        meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
        proof_tier = str(meta.get("proof") or "doctrine-only")
        cat = MISSION_CATEGORIES.get(name, "Other")
        if proof and proof_tier != proof:
            continue
        if category and cat.lower() != category.lower():
            continue
        desc = str(fm.get("description") or "")
        main_desc, use_when, not_for = _split_description(desc)
        body = _split_body(text)
        clause = sorted(grammar.clause_refs(body))
        deferred = sorted(grammar.deferred_declared(body))
        cap_entry = caps.get(name, {}) if isinstance(caps, dict) else {}
        item: dict[str, Any] = {
            "name": name,
            "category": cat,
            "description": desc,
            "summary": main_desc,
            "use_when": use_when,
            "not_for": not_for,
            "compatibility": str(fm.get("compatibility") or ""),
            "proof": proof_tier,
            "proof_evidence": str(meta.get("proof_evidence") or ""),
            "autonomy": str(meta.get("autonomy") or ""),
            "activation_budget_tokens": budgets.get(name, 0),
            "identity": {
                k: str(meta.get(k) or "")
                for k in ("unit", "state_machine", "convergence", "ordering", "parking", "oracle")
            },
            "capabilities": {
                "required": list(cap_entry.get("required") or []),
                "optional": list(cap_entry.get("optional") or []),
            },
            "composes": clause,
            "deferred_reads": deferred,
            "guide_path": f"docs/missions/{name}.md",
            "skill_path": f"skills/{name}/SKILL.md",
        }
        if include_body:
            item["body"] = body
            item["convergence_section"] = _extract_section(body, "Convergence proof")
            item["anti_patterns"] = _extract_section(body, "Anti-patterns")
            item["launch_prompt"] = build_launch_prompt(item)
        missions.append(item)
    return missions


def get_mission(name: str, root: Path | None = None) -> dict[str, Any] | None:
    base = root or find_catalog_root()
    for item in list_missions(base, include_body=True):
        if item["name"] == name:
            return item
    return None


def build_launch_prompt(mission: dict[str, Any], goal: str = "") -> str:
    """Generate a clean, copy-ready prompt for invoking a mission in any coding agent."""
    name = mission["name"]
    goal_text = goal.strip() or "<describe your bounded goal, target PR/issue, or spec path>"
    if name == "review-it":
        return (
            f"Run {name}: {goal_text}\n"
            "Pin the exact head SHA, dispatch parallel read-only reviewers across acceptance axes "
            "plus triggered risk lenses, and return a quote-backed GO/NO-GO verdict without editing code."
        )
    if name == "ship-it":
        return (
            f"Run {name}: {goal_text}\n"
            "Preflight against a dedicated integration BASE branch (never main), grill & freeze the spec "
            "at a human gate, dispatch isolated vertical slices with negative controls, and stop at the promotion PR."
        )
    if name == "clean-sweep":
        return (
            f"Run {name}: {goal_text}\n"
            "Freeze the T0 finding denominator, open one PR per finding on an integration BASE branch "
            "backed by a pre-fix RED test and negative control, and re-enumerate until DRY."
        )
    return (
        f"Run {name}: {goal_text}\n"
        f"Follow skills/{name}/SKILL.md: preflight first, honor one-way human gates, "
        "bind every unit to a SHA-verified evidence manifest, and stop at the authorized terminal state."
    )


def route_intent(
    prompt: str,
    root: Path | None = None,
    *,
    top_k: int = 5,
) -> dict[str, Any]:
    """Rank missions for a user's natural-language goal using the catalog's own metadata & synonyms."""
    base = root or find_catalog_root()
    routing_cfg = _read_json(base / "evals" / "routing.json", {})
    scoring = routing_cfg.get("scoring") if isinstance(routing_cfg, dict) else {}
    synonyms = routing_cfg.get("synonyms") if isinstance(routing_cfg, dict) else {}
    name_w = float(scoring.get("name_weight", 2.0))
    use_w = float(scoring.get("use_when_weight", 3.0))
    excl_w = float(scoring.get("exclusion_weight", -0.5))
    min_evidence = float(scoring.get("min_evidence", 0.3))

    missions = list_missions(base)
    if not prompt.strip() or not missions:
        return {"query": prompt, "matches": [], "recommended": None, "above_floor": False}

    query_tokens = _tokenize(prompt, synonyms)
    if not query_tokens:
        return {"query": prompt, "matches": [], "recommended": None, "above_floor": False}

    # Build document term frequencies and document frequency across missions.
    doc_weights: list[dict[str, float]] = []
    df: dict[str, int] = {}
    for m in missions:
        weights: dict[str, float] = {}
        name_toks = _tokenize(m["name"].replace("-", " "), synonyms)
        main_toks = _tokenize(m["summary"] + " " + m["identity"].get("unit", ""), synonyms)
        use_toks = _tokenize(m["use_when"], synonyms)
        not_toks = _tokenize(m["not_for"], synonyms)
        seen_pos: set[str] = set()
        for tok in name_toks:
            weights[tok] = weights.get(tok, 0.0) + name_w
            seen_pos.add(tok)
        for tok in main_toks:
            weights[tok] = weights.get(tok, 0.0) + 1.0
            seen_pos.add(tok)
        for tok in use_toks:
            weights[tok] = weights.get(tok, 0.0) + use_w
            seen_pos.add(tok)
        for tok in not_toks:
            if tok not in seen_pos:
                weights[tok] = weights.get(tok, 0.0) + excl_w
        for tok in seen_pos:
            df[tok] = df.get(tok, 0) + 1
        doc_weights.append(weights)

    n_docs = len(missions)
    q_counts: dict[str, float] = {}
    for tok in query_tokens:
        q_counts[tok] = q_counts.get(tok, 0.0) + 1.0

    def _idf(tok: str) -> float:
        return math.log((n_docs + 1.0) / (df.get(tok, 0) + 1.0)) + 1.0

    q_vec = {tok: tf * _idf(tok) for tok, tf in q_counts.items()}
    q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0

    lower_prompt = prompt.lower()
    ranked: list[dict[str, Any]] = []
    for m, d_tf in zip(missions, doc_weights, strict=True):
        d_vec = {tok: w * _idf(tok) for tok, w in d_tf.items()}
        d_norm = math.sqrt(sum(v * v for v in d_vec.values())) or 1.0
        dot = sum(q_vec[tok] * d_vec.get(tok, 0.0) for tok in q_vec)
        evidence = dot / d_norm
        score = dot / (q_norm * d_norm)
        # Direct mention of the mission name gets an explicit signal boost.
        if m["name"] in lower_prompt:
            score += 0.55
            evidence = max(evidence, min_evidence + 0.5)
        matched_terms = sorted({tok for tok in q_vec if d_tf.get(tok, 0.0) > 0})
        ranked.append({
            "mission": m["name"],
            "score": round(score, 4),
            "evidence": round(evidence, 4),
            "proof": m["proof"],
            "category": m["category"],
            "summary": m["summary"],
            "use_when": m["use_when"],
            "not_for": m["not_for"],
            "activation_budget_tokens": m["activation_budget_tokens"],
            "required_capabilities": m["capabilities"]["required"],
            "matched_terms": matched_terms,
            "launch_prompt": build_launch_prompt(m, prompt),
        })

    ranked.sort(key=lambda r: (-r["score"], r["mission"]))
    top = ranked[: max(1, top_k)]
    best = top[0] if top else None
    above_floor = bool(best and best["evidence"] >= min_evidence)
    return {
        "query": prompt,
        "min_evidence": min_evidence,
        "above_floor": above_floor,
        "recommended": best if above_floor else None,
        "matches": top,
    }


def certification_summary(root: Path | None = None) -> dict[str, Any]:
    """Summarize provider and harness certification tiers from certification.json + capabilities.json."""
    base = root or find_catalog_root()
    cert = load_certification(base)
    caps = load_capabilities(base)
    providers_out: list[dict[str, Any]] = []
    cert_providers = cert.get("providers") if isinstance(cert.get("providers"), dict) else {}
    cap_providers = caps.get("providers") if isinstance(caps.get("providers"), dict) else {}

    for pname in sorted(cap_providers):
        p_cap = cap_providers[pname]
        p_cert = cert_providers.get(pname, {})
        counts = {"live-witnessed": 0, "fixture-tested": 0, "source-only": 0, "unsupported": 0, "unavailable": 0}
        live_cells: list[dict[str, Any]] = []
        for group in p_cert.get("routes", []):
            tier = str(group.get("tier") or "unavailable")
            profiles = group.get("profiles") or []
            harnesses = group.get("harnesses") or []
            n_cells = len(profiles) * len(harnesses)
            if tier in counts:
                counts[tier] += n_cells
            if tier == "live-witnessed":
                live_cells.append({
                    "profiles": profiles,
                    "harnesses": harnesses,
                    "witnessed": group.get("witnessed") or {},
                    "evidence": group.get("evidence") or [],
                })
        upstream = p_cert.get("upstream") if isinstance(p_cert.get("upstream"), dict) else {}
        providers_out.append({
            "name": pname,
            "tier": p_cap.get("tier"),
            "upstream": p_cap.get("upstream"),
            "certified_version": upstream.get("version") or "unknown",
            "description": p_cap.get("description") or "",
            "supported_profiles": p_cap.get("supported_profiles") or [],
            "supported_harnesses": p_cap.get("supported_harnesses") or [],
            "native_capabilities": p_cap.get("native_capabilities") or [],
            "fallback_capabilities": p_cap.get("fallback_capabilities") or [],
            "cell_counts": counts,
            "live_cells": live_cells,
        })

    harnesses_out: list[dict[str, Any]] = []
    cert_harnesses = cert.get("harnesses") if isinstance(cert.get("harnesses"), dict) else {}
    for hname in sorted(cert_harnesses):
        h_cert = cert_harnesses[hname]
        counts = {"live-witnessed": 0, "fixture-tested": 0, "source-only": 0, "unsupported": 0, "unavailable": 0}
        for group in h_cert.get("routes", []):
            tier = str(group.get("tier") or "unavailable")
            profiles = group.get("profiles") or []
            if tier in counts:
                counts[tier] += len(profiles)
        upstream = h_cert.get("upstream") if isinstance(h_cert.get("upstream"), dict) else {}
        harnesses_out.append({
            "name": hname,
            "version": upstream.get("version") or "unknown",
            "cell_counts": counts,
        })

    return {
        "record_version": cert.get("record_version"),
        "recorded": cert.get("recorded"),
        "providers": providers_out,
        "harnesses": harnesses_out,
        "capabilities": caps.get("capabilities") or {},
    }


def catalog_overview(root: Path | None = None) -> dict[str, Any]:
    """High-level catalog telemetry snapshot for CLI, MCP, and Mission Control UI."""
    base = root or find_catalog_root()
    missions = list_missions(base)
    proof_counts = {"external-run": 0, "self-run": 0, "doctrine-only": 0}
    for m in missions:
        tier = m["proof"]
        if tier in proof_counts:
            proof_counts[tier] += 1
    runs = load_retained_runs(base)
    cert = certification_summary(base)
    total_live_cells = sum(p["cell_counts"]["live-witnessed"] for p in cert["providers"]) + sum(
        h["cell_counts"]["live-witnessed"] for h in cert["harnesses"]
    )
    return {
        "version": catalog_version(base),
        "root": str(base),
        "mission_count": len(missions),
        "proof_counts": proof_counts,
        "provider_count": len(cert["providers"]),
        "harness_count": len(cert["harnesses"]),
        "live_witnessed_cells": total_live_cells,
        "retained_runs_total": len(runs),
        "retained_runs_binding": sum(1 for r in runs if r["binds_yes"]),
        "quarantine": load_quarantine(base),
        "pins": load_pins(base),
        "one_way_door_count": len(load_one_way_doors(base)),
    }
