#!/usr/bin/env python3
"""ablation.py — paired instruction-load ablations: pre-registered, generated, checked (#606).

The activation-load cap (ARCHITECTURE.md) is a ratchet with no behavioural evidence
behind it either way. #606 asks whether a smaller activation keeps a mission's task AND safety
outcomes. Answering that needs live model runs, which need the owner's spend authorisation. This
script is everything short of that spend; its live tier runs only inside the container-based
live harness (PR #668; scripts/live_container.py):

  prereg    validate docs/experiments/ablation-prereg.json (the registration) and report
            whether its pinned payloads still match the catalog; --refresh re-pins them. A
            registration whose live run is bound (`bound_run`) is frozen: its pins are checked
            at the run's commit, by that commit's own check, and --refresh refuses it
  generate  write the BASELINE and the REDUCED variant of one registered mission, mechanically,
            from the registration's `reduction` table, plus the exact payloads both arms get and
            the token delta measured by scripts/validate.py's own transitive_load
  check     re-run the static OBLIGATION CHECK on a variant directory as it is on disk (edits
            included): every registered obligation that applies to the mission must still be in
            the variant's activation text, or be deferred-loaded at a phase it allows
  run       drive both arms through the registered tasks (scripts/_ablation_run.py): an INERT
            stand-in harness by default (`--dry-run`) or an operator stub. `--tier live` runs
            only inside the container-based live harness (PR #668): anywhere else it is
            refused before anything is read, whatever the registration authorises
  report    render a results file: per-mission paired effects with uncertainty, and failures

What a variant may and may not do. The reduced arm is "minimal contract plus phase-triggered
references": a registered document leaves activation behind a `<name>.md at <PHASE>` cue keyed
to the mission's own Pipeline block, the full source lines of every registered obligation it
carried are copied verbatim into a MINIMAL CONTRACT block at activation, and registered sections
are dropped. The frontmatter is byte-identical (routing cannot move). Nothing is edited by hand,
and nothing is written over skills/: variants go to an output directory.

Why applicability is read off the BASELINE. An obligation applies to a mission when its source is
part of the mission's current activation. Reading that set off the variant would let a variant
that simply stops loading a document make that document's obligations "not applicable" — the
denominator shrinking itself, the exact failure evidence-manifest.md forbids a worker.

NOTHING here is proof evidence and nothing moves a mission's `metadata.proof` tier. Fixture and
stub results exercise the pipeline; only a live result, bound into a run report, can support the
recommendation #606 asks for, and none exists yet.

Exit: 0 ok · 1 a check failed or a run is incomplete · 2 usage, refusal or a malformed registration.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import math
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
PREREG = ROOT / "docs" / "experiments" / "ablation-prereg.json"
PREREG_MD = ROOT / "docs" / "experiments" / "ablation-prereg.md"
PREREG_SCHEMA = "open-fleet.ablation-prereg/1"
VARIANT_SCHEMA = "open-fleet.ablation-variant/1"
GENERATOR_VERSION = 1
# The four the issue names. A registration may preserve more classes, never fewer.
ISSUE_CLASSES = ("independent-verification", "negative-control", "complete-denominator",
                 "human-one-way-gate")
PENDING = "PENDING OWNER AUTHORISATION"
AUTHORISED = "AUTHORISED"
EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The activation-load measure is validate.py's, loaded by path: a second implementation is how a
# published number drifts from the gate's (#303).
validate = _load("of_ablation_validate", ROOT / "scripts" / "validate.py")
_grammar = validate._grammar

# An upper-case pipeline token: `ACCEPTANCE-REVIEW`, `DEPLOYED_AND_VERIFIED`, `STOP-THE-LINE`.
PHASE_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*)(?![A-Za-z0-9_-])")
# A cue inside a DEFERRED READS paragraph: `a.md [+ b.md] at [up to two words] PHASE[|PHASE]`.
# The same parser reads both arms, so the baseline's own phase-keyed deferrals count too.
_DOC = r"[A-Za-z0-9][A-Za-z0-9_-]*\.md"
CUE_RE = re.compile(rf"(?<![\w./-])((?:{_DOC}\s*\+\s*)*{_DOC}) at (?:[a-z]+ ){{0,2}}"
                    r"([A-Z][A-Z0-9_-]*(?:\|[A-Z][A-Z0-9_-]*)*)(?![\w-])")
HEADER = "===== {path} ====="


class AblationError(Exception):
    """A registration, mission or variant the generator refuses: exit 2, nothing written."""


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------
def norm(text):
    """Whitespace-collapsed text: anchors match across the line wraps a doc happens to have."""
    return " ".join(text.split())


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read(path):
    return Path(path).read_text(encoding="utf-8")


def frontmatter(text):
    """The leading `---` ... `---` block, verbatim ("" when there is none)."""
    m = re.match(r"---\n.*?\n---\n", text, re.S)
    return m.group(0) if m else ""


def pipeline_block(text):
    """The fenced block under `## Pipeline` (the section text when it has no fence)."""
    m = re.search(r"(?ms)^## Pipeline\b[^\n]*\n(.*?)(?=^## |\Z)", text)
    if not m:
        return ""
    fence = re.search(r"```[^\n]*\n(.*?)```", m.group(1), re.S)
    return fence.group(1) if fence else m.group(1)


def pipeline_phases(text):
    """Upper-case tokens of the Pipeline block: the only names a cue may key a phase to."""
    return {tok for tok in PHASE_RE.findall(pipeline_block(text)) if len(tok) >= 3}


def clause_protocols(text):
    """Protocols the Composes/rides clause makes mandatory (validate.py's own reader)."""
    return _grammar.clause_refs(text) & validate.known_protocol_names()


def root_docs(text):
    return set(validate.ROOT_DOC_RE.findall(text))


def doc_name(rel):
    """`runtime/evidence-manifest.md` -> `evidence-manifest`; `ARCHITECTURE.md` -> `ARCHITECTURE`."""
    return Path(rel).name[: -len(".md")] if rel.endswith(".md") else Path(rel).name


def protocol_path(name):
    """Repo-relative path of a playbook, runtime policy or root document, or None."""
    for rel in (f"playbooks/{name}.md", f"runtime/{name}.md", f"{name}.md"):
        if (ROOT / rel).is_file():
            return rel
    return None


def deferred_cues(text):
    """{document name: [phases]} from every DEFERRED READS paragraph's phase-keyed cues."""
    cues = {}
    for para in _grammar.DEFERRED_RE.findall(text):
        for docs, phases in CUE_RE.findall(para):
            for doc in re.findall(_DOC, docs):
                listed = cues.setdefault(doc[: -len(".md")], [])
                listed.extend(p for p in phases.split("|") if p not in listed)
    return cues


def anchor_span(text, anchor):
    """(first, last) 1-based source lines covering `anchor` (whitespace-normalised), or None."""
    tokens, owners = [], []
    for lineno, line in enumerate(text.splitlines(), 1):
        for tok in line.split():
            tokens.append(tok)
            owners.append(lineno)
    joined = " ".join(tokens)
    at = joined.find(norm(anchor))
    if at < 0 or not anchor.strip():
        return None
    end = at + len(norm(anchor)) - 1
    starts, pos = [], 0
    for tok in tokens:
        starts.append(pos)
        pos += len(tok) + 1
    first = max(i for i, s in enumerate(starts) if s <= at)
    last = max(i for i, s in enumerate(starts) if s <= end)
    return owners[first], owners[last]


# ---------------------------------------------------------------------------
# the registration
# ---------------------------------------------------------------------------
def load_prereg(path=PREREG):
    try:
        data = json.loads(read(path))
    except (OSError, ValueError) as err:
        raise AblationError(f"{path}: unreadable registration ({err})") from err
    if not isinstance(data, dict):
        raise AblationError(f"{path}: the registration must be a JSON object")
    return data


def mission_text(mission):
    path = SKILLS_DIR / mission / "SKILL.md"
    if not _grammar.NAME_RE.match(mission or "") or not path.is_file():
        raise AblationError(f"no mission {mission!r} in skills/")
    return read(path)


def applicable_obligations(mission, prereg):
    """Registered obligations whose source is part of the mission's BASELINE activation."""
    _total, parts = validate.transitive_load(SKILLS_DIR / mission)
    return [ob for ob in prereg.get("obligations") or [] if ob.get("source") in parts]


def _phase_ok(phase):
    return phase == "activation" or (isinstance(phase, str) and PHASE_RE.fullmatch(phase))


def prereg_errors(prereg):
    """Everything wrong with a registration, as messages; [] when it can drive a run."""
    errors = []
    if prereg.get("schema") != PREREG_SCHEMA:
        errors.append(f"schema must be {PREREG_SCHEMA}")
    if not isinstance(prereg.get("version"), int) or prereg["version"] < 1:
        errors.append("version must be a positive integer")
    if not isinstance(prereg.get("id"), str) or not prereg["id"].strip():
        errors.append("id must name the registration: it is the identity a spent run is held to")
    if prereg.get("issue") != 606:
        errors.append("issue must be 606")
    mix = [row.get("mission") for row in prereg.get("mission_mix") or [] if isinstance(row, dict)]
    if not mix or len(set(mix)) != len(mix):
        errors.append("mission_mix must name at least one mission, each once")
    missions = (prereg.get("reduction") or {}).get("missions") or {}
    preserved = prereg.get("preserved_classes") or []
    required = prereg.get("required_classes") or []
    missing = [c for c in ISSUE_CLASSES if c not in required or c not in preserved]
    if missing:
        errors.append(f"required_classes and preserved_classes must keep {missing} (#606)")
    seeds, repeats = prereg.get("seeds"), prereg.get("repeats")
    if not isinstance(repeats, int) or repeats < 1 or not isinstance(seeds, list) \
            or len(seeds) != repeats or not all(isinstance(s, int) for s in seeds):
        errors.append("seeds must be a list of integers, one per repeat")
    errors += _obligation_errors(prereg)
    errors += _task_errors(prereg, mix)
    for mission in mix:
        try:
            text = mission_text(mission)
        except AblationError as err:
            errors.append(str(err))
            continue
        spec = missions.get(mission)
        if not isinstance(spec, dict):
            errors.append(f"{mission}: no reduction.missions entry")
            continue
        errors += [f"{mission}: {e}" for e in _reduction_errors(text, spec)]
        classes = {ob.get("class") for ob in applicable_obligations(mission, prereg)}
        for cls in preserved:
            if cls not in classes:
                errors.append(f"{mission}: no registered obligation of class {cls} applies — "
                              "register one before ablating this mission")
    errors += _cap_errors(prereg.get("cost_cap"))
    errors += _harness_errors(prereg.get("harness"))
    errors += _analysis_errors(prereg.get("analysis"), prereg.get("prompt"))
    if not isinstance(prereg.get("registered_payloads"), dict):
        errors.append("registered_payloads must be an object (prereg --refresh writes it)")
    return errors


def _obligation_errors(prereg):
    errors, seen = [], set()
    for ob in prereg.get("obligations") or []:
        oid = ob.get("id") if isinstance(ob, dict) else None
        if not oid or oid in seen:
            errors.append(f"obligation {oid!r}: ids must be present and unique")
            continue
        seen.add(oid)
        source, anchor = ob.get("source"), ob.get("anchor")
        if not isinstance(ob.get("class"), str) or not ob["class"]:
            errors.append(f"obligation {oid}: needs a class")
        load_by = ob.get("load_by")
        if not isinstance(load_by, list) or not load_by or not all(map(_phase_ok, load_by)):
            errors.append(f"obligation {oid}: load_by must list `activation` and/or PHASE names")
        if not isinstance(source, str) or not (ROOT / source).is_file() or ".." in Path(source).parts:
            errors.append(f"obligation {oid}: source {source!r} is not a repository file")
        elif not isinstance(anchor, str) or anchor_span(read(ROOT / source), anchor) is None:
            # The registered obligation text is gone from its source: the registration is stale
            # and must be re-registered (a new version), never silently relaxed.
            errors.append(f"obligation {oid}: anchor not found in {source}")
    if not seen:
        errors.append("obligations must register at least one obligation")
    return errors


def _task_errors(prereg, mix):
    errors = []
    tasks = prereg.get("tasks") or {}
    cases = (tasks.get("behavioral") or {}).get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("tasks.behavioral.cases must list eval ids")
        cases = []
    for mission in mix:
        path = SKILLS_DIR / str(mission) / "evals" / "evals.json"
        try:
            ids = {ev.get("id") for ev in json.loads(read(path)).get("evals") or []}
        except (OSError, ValueError):
            errors.append(f"{mission}: unreadable {path.relative_to(ROOT)}")
            continue
        for case in cases:
            if case not in ids:
                errors.append(f"{mission}: behavioral case {case!r} is not in its evals.json")
    traj = (tasks.get("trajectories") or {}).get("cases")
    suite = json.loads(read(ROOT / "evals" / "adversarial-trajectories.json"))
    known = {c["id"] for c in suite["cases"]}
    if not isinstance(traj, list):
        errors.append("tasks.trajectories.cases must be a list")
    else:
        errors += [f"trajectory case {c!r} is not in evals/adversarial-trajectories.json"
                   for c in traj if c not in known]
    return errors


def _reduction_errors(text, spec):
    errors = []
    defer, drops = spec.get("defer"), spec.get("drop_sections", [])
    if not isinstance(defer, dict) or not isinstance(drops, list):
        return ["defer must be an object and drop_sections a list"]
    allowed = clause_protocols(text) | {doc_name(d) for d in root_docs(text)}
    phases = pipeline_phases(text)
    for name, keyed in defer.items():
        if name.endswith(".md"):
            name = name[: -len(".md")]
        if name not in allowed:
            errors.append(f"defer names {name!r}, which the mission does not load at activation")
        if not isinstance(keyed, list) or not keyed:
            errors.append(f"defer {name}: needs at least one phase")
            continue
        for phase in keyed:
            if phase not in phases:
                errors.append(f"defer {name}: phase {phase!r} is not an upper-case token of the "
                              "mission's Pipeline block")
    for title in drops:
        if not re.search(rf"(?m)^## {re.escape(str(title))}[ \t]*$", text):
            errors.append(f"drop_sections names {title!r}, which is not a `## ` section")
    return errors


def _cap_errors(cap):
    if not isinstance(cap, dict):
        return ["cost_cap must be an object"]
    errors = []

    def money(key, positive=True):
        value = cap.get(key)
        ok = isinstance(value, (int, float)) and not isinstance(value, bool) \
            and math.isfinite(value) and (value > 0 if positive else value >= 0)
        if not ok:
            errors.append(f"cost_cap.{key} must be a {'positive' if positive else 'non-negative'} finite number")

    money("proposed_usd")
    money("max_cost_per_agent_run_usd")
    money("grader_reserve_usd")
    fraction = cap.get("harness_limit_fraction")
    if (not isinstance(fraction, (int, float)) or isinstance(fraction, bool)
            or not math.isfinite(fraction) or not 0 < fraction <= 1):
        errors.append("cost_cap.harness_limit_fraction must be in (0, 1]: a call's limit sits at or "
                      "below its reservation")
    status = cap.get("status")
    if status == PENDING:
        if cap.get("authorised_usd") is not None or cap.get("authorised_by") is not None:
            errors.append("cost_cap: a PENDING cap carries no authorised amount or authoriser")
    elif status == AUTHORISED:
        money("authorised_usd")
        if not isinstance(cap.get("authorised_by"), str) or not cap["authorised_by"].strip():
            errors.append("cost_cap: an AUTHORISED cap names who authorised it")
    else:
        errors.append(f"cost_cap.status must be {PENDING!r} or {AUTHORISED!r}")
    return errors


GRADER_OUTPUTS = ("claude-json", "text")


def _harness_errors(harness):
    """The per-call limit is what makes the live spend guard pre-emptive (#652 review)."""
    if not isinstance(harness, dict):
        return ["harness must be an object"]
    errors = [f"harness.{key} must name the harness's per-call spend-limit flag"
              for key in ("agent_limit_flag", "grader_limit_flag")
              if not isinstance(harness.get(key), str) or not harness[key].startswith("-")]
    if harness.get("grader_output") not in GRADER_OUTPUTS:
        errors.append(f"harness.grader_output must be one of {GRADER_OUTPUTS}")
    if not isinstance(harness.get("grader_cmd_default"), str) or not harness["grader_cmd_default"].strip():
        errors.append("harness.grader_cmd_default must be a command")
    return errors


def _analysis_errors(analysis, prompt):
    errors = []
    analysis = analysis if isinstance(analysis, dict) else {}
    if not isinstance(analysis.get("bootstrap_resamples"), int) or analysis["bootstrap_resamples"] < 100:
        errors.append("analysis.bootstrap_resamples must be an integer >= 100")
    if not isinstance(analysis.get("bootstrap_seed"), int):
        errors.append("analysis.bootstrap_seed must be an integer")
    margin = analysis.get("non_inferiority_margin")
    if not isinstance(margin, (int, float)) or not 0 < margin < 1:
        errors.append("analysis.non_inferiority_margin must be in (0, 1)")
    prompt = prompt if isinstance(prompt, dict) else {}
    template = prompt.get("template", "")
    if not all(f"{{{k}}}" in template for k in ("payload", "run_protocol", "task")):
        errors.append("prompt.template must carry {payload}, {run_protocol} and {task}")
    if "{catalog}" not in prompt.get("run_protocol", ""):
        errors.append("prompt.run_protocol must carry {catalog}")
    return errors


# ---------------------------------------------------------------------------
# output safety
# ---------------------------------------------------------------------------
# What generation and a run READ, and so must never write over (#652 review, P1:
# `generate --out skills` deleted the real skills/ship-it at its rmtree). The registration's own
# directory is here too: only `prereg --refresh` writes it, under the narrower SOURCE_ROOTS check.
SOURCE_ROOTS = ("skills", "playbooks", "runtime", "evals")
READ_ROOTS = SOURCE_ROOTS + ("docs/experiments",)


def protected_paths(prereg=None, roots=READ_ROOTS):
    paths = {ROOT / rel for rel in roots}
    if roots is READ_ROOTS:
        paths |= set(ROOT.glob("[A-Z]*.md"))  # root documents a mission may link
        paths |= {ROOT / ob["source"] for ob in (prereg or {}).get("obligations") or []
                  if isinstance(ob, dict) and isinstance(ob.get("source"), str)}
    return {path.resolve() for path in paths}


def output_overlap(path, prereg=None, roots=READ_ROOTS):
    """The protected path `path` resolves inside, equals or contains, or None. Resolving follows
    symlinks, so a link into skills/ is skills/."""
    target = Path(path).resolve()
    for guarded in sorted(protected_paths(prereg, roots)):
        if target == guarded or guarded in target.parents or target in guarded.parents:
            return guarded
    return None


def safe_output(path, prereg=None, roots=READ_ROOTS):
    """`path` as an absolute, resolved path, or AblationError before anything is deleted or written."""
    hit = output_overlap(path, prereg, roots)
    if hit is not None:
        where = hit.relative_to(ROOT.resolve()) if ROOT.resolve() in hit.parents else hit
        raise AblationError(f"refusing to write at {path}: it overlaps the repository's {where} "
                            "(inside, equal to, or containing it); choose an output outside the sources")
    return Path(path).resolve()


# ---------------------------------------------------------------------------
# the generator
# ---------------------------------------------------------------------------
def _drop_section(text, title):
    pattern = re.compile(rf"(?ms)^## {re.escape(title)}[ \t]*\n.*?(?=^## |\Z)")
    new, count = pattern.subn("", text, count=1)
    if count != 1:
        raise AblationError(f"no `## {title}` section to drop")
    return new.rstrip("\n") + "\n"


def _rewrite_clause(clause, names):
    for name in names:
        clause = clause.replace(f"`{name}`", f"{name} (deferred)")
        clause = re.sub(rf"(?<![\w./-]){re.escape(name)}\.md\b", f"{name} (deferred)", clause)
    return clause


def _rewrite(text, protocols, roots):
    """Plain-word every deferred name in the body's Composes/rides clauses and root links."""
    head = len(frontmatter(text))
    body = text[head:]
    out, pos = [], 0
    for m in _grammar.COMPOSE_CLAUSE_RE.finditer(body):
        start, end = m.span(1)
        out += [body[pos:start], _rewrite_clause(body[start:end], protocols)]
        pos = end
    body = "".join(out) + body[pos:]
    for doc in roots:
        body = re.sub(rf"\[([^\]]*)\]\((?:\.\./)+{re.escape(doc)}\)",
                      lambda m: f"{m.group(1)} (deferred)", body)
    return text[:head] + body


def _contract_block(groups):
    """The MINIMAL CONTRACT paragraphs: each source line range once, with the ids it carries."""
    paras = ["MINIMAL CONTRACT (ablation variant, R13/#606): the obligation-bearing lines of "
             "every deferred document, verbatim, kept at activation."]
    for source in sorted(groups):
        lines = read(ROOT / source).splitlines()
        merged = []
        for first, last, oid in sorted(groups[source]):
            if merged and first <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], last)
                merged[-1][2].append(oid)
            else:
                merged.append([first, last, [oid]])
        for first, last, ids in merged:
            where = f"{source}:{first}" if first == last else f"{source}:{first}-{last}"
            paras.append(f"[{', '.join(ids)}] {where}\n" + "\n".join(lines[first - 1:last]))
    return "\n\n".join(paras)


def _deferred_paragraph(defer):
    cues = " · ".join(f"{name}.md at {'|'.join(phases)}" for name, phases in defer.items())
    return ("DEFERRED READS (ablation variant, R13/#606), loaded ON ENTERING the first listed "
            f"phase and never at activation: {cues}.")


def reduce_text(mission, prereg):
    """(variant SKILL.md text, {deferred name: phases}, [extracted obligation ids]). Pure."""
    text = mission_text(mission)
    spec = ((prereg.get("reduction") or {}).get("missions") or {}).get(mission)
    if not isinstance(spec, dict):
        raise AblationError(f"{mission} has no registered reduction: it is not in the mix")
    problems = _reduction_errors(text, spec)
    if problems:
        raise AblationError(f"{mission}: " + "; ".join(problems))
    defer = {name[: -len(".md")] if name.endswith(".md") else name: list(phases)
             for name, phases in spec["defer"].items()}
    roots = sorted(d for d in root_docs(text) if doc_name(d) in defer)
    protocols = sorted(n for n in defer if f"{n}.md" not in roots)
    variant = text
    for title in spec.get("drop_sections", []):
        variant = _drop_section(variant, title)
    variant = _rewrite(variant, protocols, roots)
    # R3: an obligation whose source leaves activation is copied in, unless its own load_by
    # already allows every phase the source is deferred to.
    groups, extracted = {}, []
    for ob in applicable_obligations(mission, prereg):
        name = doc_name(ob["source"])
        if name not in defer or set(defer[name]) <= set(ob["load_by"]) - {"activation"}:
            continue
        span = anchor_span(read(ROOT / ob["source"]), ob["anchor"])
        if span is None:
            raise AblationError(f"obligation {ob['id']}: anchor not found in {ob['source']}")
        groups.setdefault(ob["source"], []).append((span[0], span[1], ob["id"]))
        extracted.append(ob["id"])
    head = len(frontmatter(variant))
    first = next(iter(_grammar.COMPOSE_CLAUSE_RE.finditer(variant[head:])), None)
    if first is None:
        raise AblationError(f"{mission}: no Composes/rides clause to anchor the generated blocks")
    at = head + first.end(1)
    blocks = [_deferred_paragraph(defer)] + ([_contract_block(groups)] if groups else [])
    variant = variant[:at] + "\n\n" + "\n\n".join(blocks) + variant[at:]
    return variant, defer, extracted


def activation_payload(skill_dir, parts):
    """The exact text an arm's coordinator is handed: every counted file, in transitive_load order."""
    chunks = []
    for rel in parts:
        path = Path(skill_dir) / "SKILL.md" if rel.startswith("skills/") else ROOT / rel
        chunks.append(HEADER.format(path=rel) + "\n" + read(path).rstrip("\n") + "\n")
    return "\n".join(chunks)


def generate(mission, prereg, out_root):
    """Write both arms of one mission under out_root/<mission>/ and return the variant record."""
    variant_text, defer, extracted = reduce_text(mission, prereg)
    base_dir = SKILLS_DIR / mission
    # Both the root and the mission directory: a symlink planted at out/<mission> resolves too.
    safe_output(out_root, prereg)
    mission_out = safe_output(Path(out_root) / mission, prereg)
    if mission_out.exists():
        shutil.rmtree(mission_out)
    red_dir = mission_out / "reduced" / "skills" / mission
    red_dir.mkdir(parents=True)
    (red_dir / "SKILL.md").write_text(variant_text, encoding="utf-8")
    base_total, base_parts = validate.transitive_load(base_dir)
    red_total, red_parts = validate.transitive_load(red_dir)
    # R5: what validate.py counts for the variant must be exactly the registered kept set — a
    # leftover backtick or `name.md` in a clause would otherwise be counted and never noticed.
    counted = {doc_name(rel) for rel in red_parts if not rel.startswith("skills/")}
    kept = {doc_name(rel) for rel in base_parts if not rel.startswith("skills/")} - set(defer)
    if counted != kept:
        raise AblationError(f"{mission}: the variant's measured activation {sorted(counted)} is "
                            f"not the registered kept set {sorted(kept)}")
    base_payload = activation_payload(base_dir, base_parts)
    red_payload = activation_payload(red_dir, red_parts)
    (mission_out / "baseline.payload.md").write_text(base_payload, encoding="utf-8")
    (mission_out / "reduced.payload.md").write_text(red_payload, encoding="utf-8")
    check = check_obligations(mission, red_dir, prereg)
    record = {
        "schema": VARIANT_SCHEMA,
        "generator_version": GENERATOR_VERSION,
        "mission": mission,
        "prereg": {"version": prereg.get("version"), "sha256": prereg_sha256(prereg)},
        "inputs": {rel: sha256_text(read(ROOT / rel)) for rel in sorted(base_parts)},
        "baseline": {"skill_dir": str(base_dir), "tokens": base_total, "parts": base_parts,
                     "payload_sha256": sha256_text(base_payload)},
        "reduced": {"skill_dir": str(red_dir), "tokens": red_total, "parts": red_parts,
                    "payload_sha256": sha256_text(red_payload)},
        "delta_tokens": red_total - base_total,
        "deferred": [{"name": n, "path": protocol_path(n), "phases": p} for n, p in defer.items()],
        "kept": sorted(kept),
        "dropped_sections": list(((prereg["reduction"]["missions"][mission]) or {})
                                 .get("drop_sections", [])),
        "minimal_contract": extracted,
        "obligation_check": check,
    }
    (mission_out / "variant.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


# ---------------------------------------------------------------------------
# the static obligation check
# ---------------------------------------------------------------------------
def check_obligations(mission, variant_dir, prereg):
    """Does every registered obligation that applies to the mission survive in this variant?

    `variant_dir` is a skill directory whose SKILL.md is read AS IT IS ON DISK, so a variant
    edited after generation is checked on its edits. Applicability comes from the baseline.
    """
    base_text = mission_text(mission)
    applicable = applicable_obligations(mission, prereg)
    failures = []
    classes = {ob["class"] for ob in applicable}
    for cls in prereg.get("preserved_classes") or ISSUE_CLASSES:
        if cls not in classes:
            failures.append(f"class {cls}: no registered obligation applies to {mission}, so its "
                            "survival cannot be shown")
    variant_md = Path(variant_dir) / "SKILL.md"
    try:
        vtext = read(variant_md)
    except OSError as err:
        return {"passed": False, "results": [], "failures": [f"unreadable variant: {err}"]}
    if frontmatter(vtext) != frontmatter(base_text):
        failures.append("frontmatter differs from the baseline: routing is no longer invariant")
    _total, vparts = validate.transitive_load(Path(variant_dir))
    activation = norm("\n".join([vtext] + [read(ROOT / rel) for rel in vparts
                                           if not rel.startswith("skills/")]))
    cues = deferred_cues(vtext)
    results = []
    for ob in applicable:
        anchor = norm(ob["anchor"])
        name = doc_name(ob["source"])
        phases = cues.get(name) if not ob["source"].startswith("skills/") else None
        allowed = set(ob["load_by"]) - {"activation"}
        if anchor in activation:
            row = {"held": True, "where": "activation"}
        elif phases and anchor in norm(read(ROOT / ob["source"])):
            if set(phases) <= allowed:
                row = {"held": True, "where": f"deferred at {'|'.join(phases)}"}
            else:
                row = {"held": False, "where": f"deferred at {'|'.join(phases)}",
                       "why": f"its source is deferred to {'|'.join(phases)}, but the obligation "
                              f"must be loaded by {'|'.join(ob['load_by'])}"}
        else:
            row = {"held": False, "where": "nowhere",
                   "why": "dropped: not in the variant's activation text and its source is not "
                          "deferred-loaded"}
        row.update({"id": ob["id"], "class": ob["class"], "source": ob["source"]})
        results.append(row)
        if not row["held"]:
            failures.append(f"{ob['id']} ({ob['class']}): {row['why']}")
    return {"passed": not failures, "results": results, "failures": failures}


# ---------------------------------------------------------------------------
# registration digests
# ---------------------------------------------------------------------------
def prereg_sha256(prereg):
    """Digest of the registration as committed (sorted keys, so formatting cannot move it)."""
    return sha256_text(json.dumps(prereg, sort_keys=True, ensure_ascii=False))


def task_inputs(mission, prereg):
    """{repo path: sha256 | "missing"} of every input the mission's registered tasks start from:
    its evals.json, each fixture file a registered behavioral case names, the #602 suite with its
    frozen contract, and the recordings of the registered trajectory cases (#652 review: an edit
    to any of these changes the experiment, so it must make the registration stale)."""
    paths = {f"skills/{mission}/evals/evals.json", "evals/adversarial-trajectories.json"}
    try:
        evals = json.loads(read(ROOT / f"skills/{mission}/evals/evals.json")).get("evals") or []
    except (OSError, ValueError):
        evals = []
    cases = set((prereg.get("tasks") or {}).get("behavioral", {}).get("cases") or [])
    for ev in evals:
        if isinstance(ev, dict) and ev.get("id") in cases:
            paths |= {f"skills/{mission}/evals/fixtures/{entry}" for entry in ev.get("files") or []
                      if isinstance(entry, str)}
    try:
        suite = json.loads(read(ROOT / "evals" / "adversarial-trajectories.json"))
    except (OSError, ValueError):
        suite = {}
    if isinstance((suite.get("contract") or {}).get("path"), str):
        paths.add(suite["contract"]["path"])
    registered = set((prereg.get("tasks") or {}).get("trajectories", {}).get("cases") or [])
    for case in suite.get("cases") or []:
        if case.get("id") in registered:
            paths |= {f"evals/trajectories/{rec['file']}" for rec in case.get("trajectories") or []}
    return {rel: file_sha256(ROOT / rel) if (ROOT / rel).is_file() else "missing"
            for rel in sorted(paths)}


def measure(prereg, missions=None):
    """{mission: payload digests and loads} for the catalog as it is now."""
    out = {}
    with tempfile.TemporaryDirectory(prefix="of-ablation-measure-") as tmp:
        for mission in missions or [row["mission"] for row in prereg["mission_mix"]]:
            rec = generate(mission, prereg, tmp)
            out[mission] = {
                "baseline_sha256": rec["baseline"]["payload_sha256"],
                "reduced_sha256": rec["reduced"]["payload_sha256"],
                "baseline_tokens": rec["baseline"]["tokens"],
                "reduced_tokens": rec["reduced"]["tokens"],
                "delta_tokens": rec["delta_tokens"],
                "obligations_held": rec["obligation_check"]["passed"],
                "task_inputs_sha256": sha256_text(json.dumps(task_inputs(mission, prereg),
                                                             sort_keys=True)),
            }
    return out


def registration_status(prereg):
    """{mission: "current" | "stale: ..." | "unregistered"} against the catalog and the registered
    tasks' inputs now."""
    pinned = prereg.get("registered_payloads") or {}
    status = {}
    for mission, now in measure(prereg).items():
        then = pinned.get(mission)
        if not then:
            status[mission] = "unregistered"
        elif then == now:
            status[mission] = "current"
        else:
            moved = sorted(k for k in now if then.get(k) != now[k])
            status[mission] = f"stale: {', '.join(moved)} moved since registration"
    return status


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


LOADS_BLOCK = re.compile(r"(<!-- BEGIN GENERATED: ablation-loads[^\n]*-->\n)(.*?)(<!-- END GENERATED: ablation-loads -->)",
                         re.S)
REGISTRATION_LINE = re.compile(r"(?m)^Registration: \*\*version (\d+)\*\*, `docs/experiments/"
                               r"ablation-prereg\.json` sha256 `([0-9a-f]{64})`\.$")


def loads_table(pinned):
    """The registration page's token table, generated from registered_payloads (never typed)."""
    rows = ["| Mission | Baseline activation | Reduced activation | Delta |", "|---|---|---|---|"]
    rows += [f"| {m} | ~{p['baseline_tokens']:,} | ~{p['reduced_tokens']:,} | {p['delta_tokens']:+,} |"
             for m, p in pinned.items()]
    return "\n".join(rows) + "\n"


def md_sync_errors(json_path=PREREG, md_path=PREREG_MD):
    """The human registration must name the JSON's version and exact bytes, and show its loads."""
    try:
        md = read(md_path)
    except OSError as err:
        return [f"{md_path}: {err}"]
    errors = []
    block = LOADS_BLOCK.search(md)
    pinned = load_prereg(json_path).get("registered_payloads") or {}
    if not block or block.group(2) != loads_table(pinned):
        errors.append(f"{md_path}: the generated ablation-loads table is missing or does not "
                      "match registered_payloads — re-run `ablation.py prereg --refresh`")
    m = REGISTRATION_LINE.search(md)
    if not m:
        return errors + [f"{md_path}: no `Registration: **version N**, ... sha256 ...` line"]
    if int(m.group(1)) != load_prereg(json_path).get("version"):
        errors.append(f"{md_path}: registration line names version {m.group(1)}, the JSON another")
    if m.group(2) != file_sha256(json_path):
        errors.append(f"{md_path}: registration line pins sha256 {m.group(2)[:12]}…, not the "
                      "JSON's bytes — re-run `ablation.py prereg --refresh`")
    return errors


# ---------------------------------------------------------------------------
# a bound registration: frozen at the commit its live run ran at
# ---------------------------------------------------------------------------
# Before its run a registration must match the catalog, or the run would spend on payloads it never
# registered. After the run is bound, its pins describe what RAN, at the commit it ran at, and
# checking them against today's catalog made every later byte in a document these missions load
# (ARCHITECTURE.md, a runtime policy, the #602 suite) a stale registration and a `prereg --refresh`
# commit: five in the day after #606's run, each re-pinning payloads that never ran. A bound
# registration is checked where it ran instead: the run's own results name this registration's
# digest and the commit, that commit holds the same registration, and that commit's own
# `ablation.py prereg` still finds every pin current on that commit's own tree.
BOUND_KEY = "bound_run"
# What `prereg` reads: the catalog it measures, the scripts it runs, the registration and its page.
BOUND_PATHS = ("skills", "playbooks", "runtime", "scripts", "evals", "docs/experiments", ":(glob)*.md")
BOUND_TIMEOUT = 300
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_STATUS_LINE = re.compile(r"(?m)^([a-z0-9-]+): (.+)$")


_TOOLS = {}


def _tool(name):
    """A runtime/scripts module (gitexec, run_report), loaded once by path."""
    if name not in _TOOLS:
        _TOOLS[name] = _load(f"of_ablation_{name}", ROOT / "runtime" / "scripts" / f"{name}.py")
    return _TOOLS[name]


def _git(*args, blanks=()):
    """git under the read-side tools' hardened environment (runtime/scripts/gitexec.py). A planted
    `refs/replace/*` or graft would otherwise serve another tree under the run's own SHA, and
    _prereg_at EXECUTES what it reads (PR #705 review, Codex P1)."""
    gitexec = _tool("gitexec")
    return subprocess.run(gitexec.argv("-C", str(ROOT), *args), capture_output=True,
                          timeout=BOUND_TIMEOUT, env=gitexec.env(blanks=blanks),
                          stdin=subprocess.DEVNULL)


def _results_pinned(report, results):
    """[] when `results` is the bytes `report`'s integrity inventory records, and those are the
    bytes at the commit its RUN header names: the report is the binding, so read through it."""
    run_report = _tool("run_report")
    fields, err = run_report.parse_run_header(read(ROOT / report))
    if err:
        return [f"{report}: {err}"]
    try:
        _path, _lines, entries = run_report.inventory.load(ROOT / report)
    except run_report.inventory.InventoryError as err:
        return [f"{report}: integrity inventory: {err}"]
    rows = [row for row in entries if row[1] == results]
    if len(rows) != 1:
        return [f"{report}'s integrity inventory does not pin {results} exactly once"]
    rev = fields["inventory_at"]
    matched, _mismatched, _missing = run_report.inventory.check_entries(rows, ROOT / report, ROOT, at=rev)
    if not matched:
        return [f"{results} at {rev[:10]} is not the bytes {report}'s inventory records"]
    if file_sha256(ROOT / results) != rows[0][2]:
        return [f"{results} is not the bytes {report}'s inventory pins (edited since the run)"]
    return []


def _repo_file(rel):
    return isinstance(rel, str) and ".." not in Path(rel).parts and (ROOT / rel).is_file()


def bound_errors(prereg):
    """[] when a registration carrying `bound_run` is exactly the one its bound run ran under."""
    run = prereg.get(BOUND_KEY)
    if not isinstance(run, dict):
        return [f"{BOUND_KEY} must be an object naming the run's commit, results and report"]
    commit, results, report = run.get("commit"), run.get("results"), run.get("report")
    errors = []
    if not isinstance(commit, str) or not _FULL_SHA.fullmatch(commit):
        errors.append(f"{BOUND_KEY}.commit must be a full 40-hex commit")
    for key, rel in (("results", results), ("report", report)):
        if not _repo_file(rel):
            errors.append(f"{BOUND_KEY}.{key} {rel!r} is not a repository file")
    if errors:
        return errors
    rid = prereg.get("id")
    if (SPENT_RUNS.get(rid) if isinstance(rid, str) else None) != (prereg.get("version"), commit):
        errors.append(f"SPENT_RUNS does not record version {prereg.get('version')} of "
                      f"{rid!r} as run at {commit[:10]}: a bound run joins that ledger "
                      "with its binding, so the spent version stays spent without this file")
    if not results.startswith(report[: -len(".md")] + "/"):
        errors.append(f"{BOUND_KEY}.results must sit in the report's own run directory, which the "
                      "report's inventory binds (runtime/scripts/run_report.py)")
    try:
        ran = json.loads(read(ROOT / results))
    except (OSError, ValueError) as err:
        return errors + [f"{results}: unreadable ({err})"]
    if not isinstance(ran, dict) or not isinstance(ran.get("prereg"), dict):
        return errors + [f"{results}: not a run's results (no prereg record)"]
    pinned = ran["prereg"]
    frozen = {k: v for k, v in prereg.items() if k != BOUND_KEY}
    if ran.get("tier") != "live" or ran.get("catalog_head") != commit:
        errors.append(f"{results} is not a live run at {commit[:10]}")
    # Every registered mission, current: any map of "current" values once passed (Codex P2).
    mix = {row.get("mission") for row in prereg.get("mission_mix") or [] if isinstance(row, dict)}
    recorded = pinned.get("registration")
    if not isinstance(recorded, dict) or set(recorded) != mix or set(recorded.values()) != {"current"}:
        errors.append(f"{results} does not record every registered mission current when it ran")
    try:
        errors += _results_pinned(report, results)
    except (OSError, subprocess.SubprocessError) as err:
        errors.append(f"{report}'s inventory cannot be checked ({err})")
    try:
        shown = _git("show", f"{commit}:{PREREG.relative_to(ROOT).as_posix()}")
    except (OSError, subprocess.SubprocessError) as err:
        return errors + [f"git could not read the run commit ({err})"]
    if shown.returncode != 0:
        return errors + [f"commit {commit[:10]} or its registration is not in this clone: a bound "
                         "registration is checked at its run commit, which a shallow checkout lacks"]
    try:
        then = json.loads(shown.stdout.decode("utf-8"))
    except ValueError as err:
        return errors + [f"the registration at {commit[:10]} is unreadable ({err})"]
    if prereg_sha256(then) != pinned.get("sha256"):
        errors.append(f"the registration at {commit[:10]} is not the one {results} ran under")
    # The digest, never Python equality: 5 == 5.0 and True == 1, yet each is another registration
    # (PR #705 review, Codex P2). The keys are named the same canonical way.
    if prereg_sha256(frozen) != pinned.get("sha256"):
        def canon(value):
            return json.dumps(value, sort_keys=True, ensure_ascii=False)
        moved = sorted(k for k in set(then) | set(frozen) if canon(then.get(k)) != canon(frozen.get(k)))
        errors.append(f"a bound registration is frozen, but {', '.join(moved) or 'its digest'} changed "
                      f"since its run at {commit[:10]}: a new design is a new registration (a new "
                      "version, unbound)")
    return errors


# The ledger of bound live runs: {registration id: (its bound version, the commit it ran at)}. It is
# the authority on what is spent, not any registration file: a copy with `bound_run` deleted kept
# the bound version and its spent AUTHORISED cap (PR #705 review, Codex P1), and a file-based
# authority vanished when that file changed or would not parse (Codex P1, round 4). Append-only: a
# bound run is a one-way fact, so an entry is added beside its run's binding and never removed.
SPENT_RUNS = {
    "R13-606-activation-ablation": (2, "c220067e9cbffc4f34d6363a92153e45402bdfe4"),
}


def spent_registration(prereg):
    """(version, commit) of the bound run whose identity `prereg` reuses, or None for a new one.

    Same `id` at the bound version or below is the same, spent registration; a new run is a new
    version above it. An `id` that is not a non-empty string is no identity at all and counts as
    spent, so deleting it cannot make a registration new (prereg_errors refuses it as well)."""
    rid, version = prereg.get("id"), prereg.get("version")
    if not isinstance(rid, str) or not rid.strip():
        return next(iter(SPENT_RUNS.values()))
    spent = SPENT_RUNS.get(rid)
    if spent is None:
        return None
    newer = isinstance(version, int) and not isinstance(version, bool) and version > spent[0]
    return None if newer else spent


def bound_status(prereg):
    """{mission: state} from the run commit's own `ablation.py prereg`, run on that commit's tree.

    The catalog now is never read: the commit's code measures the commit's catalog, so an edit made
    after the run cannot move the result, and a pin that was stale when it ran still reads stale."""
    commit = prereg[BOUND_KEY]["commit"]
    proc = _prereg_at(commit)
    if proc.returncode not in (EXIT_OK, EXIT_FAILED):
        raise AblationError(f"the registration does not check at {commit[:10]}: "
                            f"{proc.stderr.strip()[:300]}")
    found = dict(_STATUS_LINE.findall(proc.stdout))
    return {m: (f"{found[m]} at {commit[:10]}" if m in found else f"unchecked at {commit[:10]}")
            for m in (row["mission"] for row in prereg["mission_mix"])}


def _prereg_at(commit):
    """The CompletedProcess of `ablation.py prereg` as `commit` has it, on `commit`'s own tree."""
    # `archive` takes the commit in option position: anything but a full SHA (`--remote=…`, `-o`)
    # is refused before git reads it — bound_status reaches here without bound_errors (W2-04).
    if not isinstance(commit, str) or not _FULL_SHA.fullmatch(commit):
        raise AblationError(f"{BOUND_KEY}.commit must be a full 40-hex commit, not {commit!r}")
    with tempfile.TemporaryDirectory(prefix="of-ablation-bound-") as tmp:
        try:
            archive = _git("archive", "--format=tar", commit, "--", *BOUND_PATHS,
                           blanks=_tool("gitexec").driver_blanks(ROOT))
            if archive.returncode != 0:
                raise AblationError(f"git archive {commit[:10]} failed: "
                                    f"{archive.stderr.decode('utf-8', 'replace').strip()[:200]}")
            with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
                # Our own history, but extracted as data all the same where Python can (3.11.4+).
                tar.extractall(tmp, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
            proc = subprocess.run([sys.executable, "-I", str(Path(tmp) / "scripts" / "ablation.py"),
                                   "prereg"], cwd=tmp, capture_output=True, text=True,
                                  timeout=BOUND_TIMEOUT)
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as err:
            raise AblationError(f"the registration cannot be checked at {commit[:10]}: {err}") from err
    return proc


def refresh(json_path=PREREG, md_path=PREREG_MD):
    """Re-pin registered_payloads to the catalog now and the md line to the JSON's bytes."""
    prereg = load_prereg(json_path)
    if BOUND_KEY in prereg or spent_registration(prereg) is not None:
        raise AblationError(f"{json_path}: refusing to re-pin a bound registration: its pins are "
                            "frozen at the commit its live run ran at (a new run is a new "
                            "registration, a new version above the bound one, without bound_run)")
    problems = [e for e in prereg_errors(prereg) if "registered_payloads" not in e]
    if problems:
        raise AblationError("refusing to re-pin a registration with errors: " + "; ".join(problems))
    for path in (json_path, md_path):
        safe_output(path, roots=SOURCE_ROOTS)
    prereg["registered_payloads"] = measure(prereg)
    body = json.dumps(prereg, indent=2, ensure_ascii=False) + "\n"
    line = (f"Registration: **version {prereg['version']}**, `docs/experiments/ablation-prereg.json` "
            f"sha256 `{sha256_text(body)}`.")
    md, count = REGISTRATION_LINE.subn(line, read(md_path))
    md, blocks = LOADS_BLOCK.subn(lambda m: m.group(1) + loads_table(prereg["registered_payloads"])
                                  + m.group(3), md)
    if count != 1 or blocks != 1:
        raise AblationError(f"{md_path}: expected exactly one registration line and one "
                            "ablation-loads block to re-pin")
    # Both files are verified before either is written, so a failure leaves neither half-pinned.
    Path(json_path).write_text(body, encoding="utf-8")
    Path(md_path).write_text(md, encoding="utf-8")
    return prereg["registered_payloads"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_RUNNER = []


def _runner():
    """The paired runner and reporter (scripts/_ablation_run.py), loaded once by path."""
    if not _RUNNER:
        _RUNNER.append(_load("of_ablation_run", ROOT / "scripts" / "_ablation_run.py"))
    return _RUNNER[0]


def cmd_prereg(args):
    if args.refresh:
        pinned = refresh(Path(args.prereg), Path(args.md))
        print(json.dumps(pinned, indent=2, sort_keys=True))
        return EXIT_OK
    prereg = load_prereg(args.prereg)
    # A spent identity is checked as bound whether or not it still carries the marker, so a spent
    # registration edited with bound_run deleted fails here too (PR #705 review, Codex P2).
    bound = BOUND_KEY in prereg or spent_registration(prereg) is not None
    # A bound registration's design checks were run at its commit, by bound_status; the catalog
    # now is not its denominator.
    errors = (bound_errors(prereg) if bound else prereg_errors(prereg)) \
        + md_sync_errors(Path(args.prereg), Path(args.md))
    for err in errors:
        print(f"ablation: prereg: {err}", file=sys.stderr)
    if errors:
        return EXIT_USAGE
    status = bound_status(prereg) if bound else registration_status(prereg)
    for mission, state in status.items():
        print(f"{mission}: {state}")
    cap = prereg["cost_cap"]
    print(f"version {prereg['version']} · cost cap {cap['status']} (proposed USD {cap['proposed_usd']})")
    if bound:
        print(f"bound: {prereg[BOUND_KEY]['report']} (frozen at {prereg[BOUND_KEY]['commit'][:10]})")
        current = all(s == f"current at {prereg[BOUND_KEY]['commit'][:10]}" for s in status.values())
    else:
        current = all(s == "current" for s in status.values())
    return EXIT_OK if current else EXIT_FAILED


def cmd_generate(args):
    prereg = load_prereg(args.prereg)
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="open-fleet-ablation-"))
    record = generate(args.mission, prereg, out)
    check = record["obligation_check"]
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"{args.mission}: baseline ~{record['baseline']['tokens']} tokens, reduced "
              f"~{record['reduced']['tokens']} ({record['delta_tokens']:+d}), "
              f"{len(record['deferred'])} deferred, minimal contract {record['minimal_contract']}")
        print(f"written under {out / args.mission}")
        print("obligations: " + ("all held" if check["passed"] else "FAILED"))
        for failure in check["failures"]:
            print(f"  - {failure}")
    return EXIT_OK if check["passed"] else EXIT_FAILED


def cmd_check(args):
    prereg = load_prereg(args.prereg)
    check = check_obligations(args.mission, Path(args.variant), prereg)
    for row in check["results"]:
        print(f"{'held ' if row['held'] else 'FAIL '} {row['id']:<11} {row['class']:<25} {row['where']}")
    for failure in check["failures"]:
        print(f"ablation: check: {failure}", file=sys.stderr)
    return EXIT_OK if check["passed"] else EXIT_FAILED


def build_parser():
    p = argparse.ArgumentParser(prog="ablation.py", description=__doc__.split("\n\n")[0],
                                epilog="exit 0 ok / 1 failed or incomplete / 2 usage or refusal")
    p.add_argument("--prereg", default=str(PREREG), help="the registration JSON")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("prereg", help="validate the registration and its pinned payloads")
    r.add_argument("--md", default=str(PREREG_MD), help="the human registration it must match")
    r.add_argument("--refresh", action="store_true",
                   help="re-pin registered_payloads and the md line (a re-registration)")
    g = sub.add_parser("generate", help="write both arms of one mission")
    g.add_argument("--mission", required=True)
    g.add_argument("--out", default=None, help="output directory (default: a new temp dir)")
    g.add_argument("--json", action="store_true")
    c = sub.add_parser("check", help="static obligation check of a variant directory")
    c.add_argument("--mission", required=True)
    c.add_argument("--variant", required=True, help="the variant's skill dir (holds SKILL.md)")
    _runner().add_run_arguments(sub)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"prereg": cmd_prereg, "generate": cmd_generate, "check": cmd_check}
    try:
        if args.command in handlers:
            return handlers[args.command](args)
        return _runner().dispatch(args, types.SimpleNamespace(**globals()))
    except AblationError as err:
        print(f"ablation: {err}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
