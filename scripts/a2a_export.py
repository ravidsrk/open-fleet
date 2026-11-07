#!/usr/bin/env python3
"""Export open-fleet missions as offline mission descriptors, or project an A2A AgentCard (#607).

The default output is open-fleet's own OFFLINE MISSION DESCRIPTOR: each `skills/<name>/SKILL.md`
frontmatter and composition clause projected into a deterministic JSON object whose
input/output contracts are bound to `runtime/evidence-manifest.md`,
`runtime/scripts/guard_text.py` and `runtime/one-way-doors.json`. Its format tags
`a2a-agent-card/v1` and `a2a-agent-card-catalog/v1` are kept for existing consumers; they name
this descriptor format, not an A2A protocol version. A descriptor is NOT an A2A transport
AgentCard -- validated against the pinned official schema (scripts/a2a_schema.py) it is refused
-- and it claims no endpoint, task execution, authentication or streaming: open-fleet serves no
A2A endpoint. `offline_claim_errors` keeps it that way.

`--standard-card` is the opt-in projection to a real `lf.a2a.v1` AgentCard (ProtoJSON) for an
A2A endpoint YOU operate. It needs `--endpoint` and `--binding`, never invents a URL, refuses
reserved placeholder hosts, keeps every mission-specific proof/governance field inside one
namespaced data-only extension, and validates the result against the pinned proto plus explicit
semantic checks before printing it. See docs/a2a-export.md.

Usage:
    python3 scripts/a2a_export.py                        # print full descriptor catalog JSON
    python3 scripts/a2a_export.py --mission ship-it      # print one mission descriptor
    python3 scripts/a2a_export.py --out dist/a2a.json    # write to file
    python3 scripts/a2a_export.py --check                # validate all mission descriptors
    python3 scripts/a2a_export.py --compare              # AgentCard fields vs the descriptor
    python3 scripts/a2a_export.py --standard-card --endpoint https://<your-host>/a2a/v1 \\
        --binding JSONRPC [--mission ship-it]            # validated lf.a2a.v1 AgentCard

Exit: 0 ok · 1 validation/export failure · 2 usage error.
"""
import argparse
import importlib.util
import ipaddress
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
DOORS_PATH = ROOT / "runtime" / "one-way-doors.json"
PLUGIN_JSON = ROOT / ".claude-plugin" / "plugin.json"

_spec = importlib.util.spec_from_file_location("_validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate)
_schema_spec = importlib.util.spec_from_file_location("_a2a_schema", ROOT / "scripts" / "a2a_schema.py")
a2a_schema = importlib.util.module_from_spec(_schema_spec)
_schema_spec.loader.exec_module(a2a_schema)

# Legacy format tags, frozen for existing consumers (docs/a2a-export.md, compatibility policy).
CARD_SCHEMA = "a2a-agent-card/v1"
CATALOG_SCHEMA = "a2a-agent-card-catalog/v1"
DESCRIPTOR_KIND = "offline-mission-descriptor"
CATALOG_KIND = "offline-mission-descriptor-catalog"

# A descriptor serves nothing, so none of these may appear in it (#607).
TRANSPORT_CLAIM_KEYS = (
    "url", "supportedInterfaces", "additionalInterfaces", "preferredTransport", "endpoint",
    "securitySchemes", "securityRequirements", "security",
)
MISSION_ONLY_KEYS = ("compatibility", "autonomy", "proof", "identity", "composition", "contracts")

STANDARD_BINDINGS = ("JSONRPC", "GRPC", "HTTP+JSON")
MISSION_EXTENSION_URI = (
    "https://github.com/ravidsrk/open-fleet/blob/main/docs/a2a-export.md#mission-extension-v1")
CATALOG_CARD_NAME = "open-fleet"
CATALOG_CARD_DESCRIPTION = (
    "open-fleet missions: outcome-named autonomous fleets on the Orca runtime, each with its own "
    "state machine and an evidence-backed definition of done.")
# The descriptor's task spec is markdown+json and its output an evidence manifest plus a report.
DEFAULT_INPUT_MODES = ("text/markdown", "application/json")
DEFAULT_OUTPUT_MODES = ("application/json", "text/markdown")
# RFC 2606 / RFC 6761 names: documentation and test placeholders, never a served endpoint.
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_TLDS = ("example", "test", "invalid", "localhost")

# Where each lf.a2a.v1 AgentCard field comes from in the --standard-card projection.
PROJECTION_SOURCES = {
    "name": "`open-fleet`, or `open-fleet <mission>` with `--mission`",
    "description": "a fixed catalog sentence, or the mission's description",
    "supportedInterfaces": "one entry from `--endpoint`, `--binding`, `--protocol-version`",
    "provider": "omitted: who operates the endpoint is not known to the exporter",
    "version": "`--agent-version` (default: `.claude-plugin/plugin.json` version)",
    "documentationUrl": "omitted",
    "capabilities": "`streaming`, `pushNotifications`, `extendedAgentCard` false; "
                    "the mission extension",
    "securitySchemes": "omitted: the exporter knows no authentication",
    "securityRequirements": "omitted: the exporter knows no authentication",
    "defaultInputModes": "`text/markdown`, `application/json`",
    "defaultOutputModes": "`application/json`, `text/markdown`",
    "skills": "one per mission: `id` `open-fleet:<mission>`, name, description, tags",
    "signatures": "omitted: the exporter does not sign",
    "iconUrl": "omitted",
}
DESCRIPTOR_ONLY_SOURCES = {
    "schema": "extension `params.descriptorSchema`",
    "kind": "dropped",
    "id": "`skills[].id`",
    **{key: f"extension `params.missions[<id>].{key}`" for key in MISSION_ONLY_KEYS},
}


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


def offline_claim_errors(descriptor):
    """Transport claims an offline descriptor must never make (empty = none made) (#607).

    No endpoint, interface or security key, and every `capabilities` flag false: open-fleet runs
    no A2A server, so a true flag would advertise task execution or streaming nobody provides.
    """
    errors = [f"{key}: an offline descriptor names no transport or authentication"
              for key in TRANSPORT_CLAIM_KEYS if key in descriptor]
    caps = descriptor.get("capabilities", {})
    if not isinstance(caps, dict):
        return errors + ["capabilities: expected an object"]
    errors += [f"capabilities.{key}: {value!r}, but an offline descriptor serves no A2A task"
               for key, value in caps.items() if value is not False]
    return errors


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
    planning = name in getattr(validate, "PLANNING_MISSIONS", {"map-it", "root-cause"})
    mission_class = "mutation" if mutating else ("planning" if planning else "report-only")
    verifier = (
        "runtime/scripts/verify.py"
        if mutating
        else ("artifact-verification" if planning else "report-only")
    )
    card = {
        "schema": CARD_SCHEMA,
        "kind": DESCRIPTOR_KIND,
        "id": f"open-fleet:{name}",
        "name": name,
        "description": description,
        "compatibility": compatibility,
        # Kept for v1 consumers, all false: no open-fleet component serves A2A tasks, streams or
        # pushes. `stateTransitionHistory` was true before #607 -- a claim nothing implemented.
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "autonomy": autonomy,
        "proof": {
            "tier": proof_tier,
            "evidence": meta.get("proof_evidence"),
            "mutating": mutating,
            "class": mission_class,
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
                "verifier": verifier,
                "failure_handover": "runtime/scripts/watchdog.py --handover",
            },
            "governance": {
                "gate_policy": "runtime/gate-classification.md",
                "one_way_doors_ref": "runtime/one-way-doors.json",
                "one_way_door_ids": list(door_ids),
            },
        },
    }
    claims = offline_claim_errors(card)
    if claims:
        raise ExportError(f"{skill_md}: offline descriptor makes transport claims: {claims}")
    return card


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
        "kind": CATALOG_KIND,
        "count": len(cards),
        "cards": cards,
    }


def _reserved_host(host):
    host = host.lower().rstrip(".")
    if host == "localhost" or any(host == d or host.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    if host.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified or ip.is_link_local


def endpoint_errors(endpoint, binding):
    """Why `endpoint` cannot be the real, supplied A2A endpoint for `binding` (empty = usable)."""
    if binding not in STANDARD_BINDINGS:
        return [f"--binding {binding!r}: expected one of {', '.join(STANDARD_BINDINGS)}"]
    if not endpoint:
        return ["--endpoint is required: open-fleet serves no A2A endpoint of its own, so a "
                "standard card needs the URL of one you operate"]
    if binding == "GRPC" and "://" not in endpoint:
        address = a2a_schema.grpc_address(endpoint)  # the card check's own parser (#636)
        if address is None:
            return [f"--endpoint {endpoint!r}: a GRPC endpoint is host:port (an IPv6 host in "
                    "brackets) or an https URL"]
        host = address[0]
    else:
        try:
            parts = a2a_schema.split_url(endpoint)  # the card check's own URL parser (#636)
        except ValueError as exc:
            return [f"--endpoint {endpoint!r}: malformed URL ({exc})"]
        host = parts.hostname or ""
        if parts.scheme != "https" or not host:
            return [f"--endpoint {endpoint!r}: expected an absolute https URL"]
        if parts.username is not None or parts.password is not None:
            return [f"--endpoint {endpoint!r}: credentials do not belong in a published card"]
    if _reserved_host(host):
        return [f"--endpoint {endpoint!r}: {host!r} is a reserved placeholder or loopback host, "
                "not an endpoint another agent can reach; supply the one you operate"]
    return []


def projection_errors(card, schema):
    """Claims the projection itself must not make, beyond the pinned schema's own checks."""
    errors = []
    caps = card.get("capabilities", {})
    for flag in ("streaming", "pushNotifications", "extendedAgentCard"):
        if caps.get(flag) is not False:
            errors.append(f"capabilities.{flag}: the exporter implements no such capability")
    for key in ("securitySchemes", "securityRequirements", "signatures"):
        if key in card:
            errors.append(f"{key}: the exporter knows no authentication and signs nothing")
    for iface in card.get("supportedInterfaces", []):
        if iface.get("protocolVersion", "").split(".")[0] != schema.major:
            errors.append(f"protocolVersion {iface.get('protocolVersion')!r}: the pinned schema "
                          f"is {schema.package}, so the major must be {schema.major}")
    ours = [e for e in caps.get("extensions", []) if e.get("uri") == MISSION_EXTENSION_URI]
    if len(ours) != 1 or ours[0].get("required") is not False:
        errors.append("capabilities.extensions: expected exactly one optional mission extension")
    else:
        skill_ids = sorted(s["id"] for s in card.get("skills", []))
        if sorted(ours[0].get("params", {}).get("missions", {})) != skill_ids:
            errors.append("mission extension params do not cover exactly the card's skills")
    return errors


def plugin_version(plugin_json=PLUGIN_JSON):
    try:
        version = json.loads(Path(plugin_json).read_text(encoding="utf-8")).get("version")
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"unreadable {plugin_json}: {exc}") from exc
    if not isinstance(version, str) or not version:
        raise ExportError(f"{plugin_json} has no version")
    return version


def build_standard_card(endpoint, binding, protocol_version="1.0", agent_version=None,
                        mission=None, skills_dir=SKILLS_DIR, doors_path=DOORS_PATH):
    """A validated lf.a2a.v1 AgentCard (ProtoJSON) for an endpoint the caller operates (#607)."""
    problems = endpoint_errors(endpoint, binding)
    if problems:
        raise ExportError("; ".join(problems))
    try:
        schema = a2a_schema.load_schema()
    except a2a_schema.ProtoSchemaError as exc:
        raise ExportError(f"pinned A2A schema unusable: {exc}") from exc
    payload = build_catalog_cards(skills_dir=skills_dir, doors_path=doors_path, mission=mission)
    descriptors = [payload] if mission is not None else payload["cards"]
    skills, missions = [], {}
    for d in descriptors:
        skills.append({
            "id": d["id"],
            "name": d["name"],
            "description": d["description"],
            "tags": ["open-fleet", "mission",
                     "mutating" if d["proof"]["mutating"] else d["proof"].get("class", "report-only"),
                     f"proof:{d['proof']['tier']}"],
        })
        missions[d["id"]] = {key: d[key] for key in MISSION_ONLY_KEYS}
    card = {
        "name": f"{CATALOG_CARD_NAME} {mission}" if mission is not None else CATALOG_CARD_NAME,
        "description": descriptors[0]["description"] if mission is not None
        else CATALOG_CARD_DESCRIPTION,
        "supportedInterfaces": [
            {"url": endpoint, "protocolBinding": binding, "protocolVersion": protocol_version},
        ],
        "version": agent_version or plugin_version(),
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "extendedAgentCard": False,
            "extensions": [{
                "uri": MISSION_EXTENSION_URI,
                "description": "Data-only: open-fleet mission proof tier, autonomy, identity, "
                               "composition and evidence/governance contracts, per skill id.",
                "required": False,
                "params": {"descriptorSchema": CARD_SCHEMA, "missions": missions},
            }],
        },
        "defaultInputModes": list(DEFAULT_INPUT_MODES),
        "defaultOutputModes": list(DEFAULT_OUTPUT_MODES),
        "skills": skills,
    }
    errors = a2a_schema.card_errors(card, schema=schema) + projection_errors(card, schema)
    if errors:
        raise ExportError(f"standard card fails the pinned {schema.package} checks: "
                          + "; ".join(errors))
    return card


def field_comparison(descriptor=None):
    """Rows comparing lf.a2a.v1 AgentCard fields with the offline descriptor (#607).

    Each AgentCard field: (field, required, descriptor status, projection source); then each
    descriptor-only key: (key, status in AgentCard, projection source). Status comes from running
    the pinned validator on a real descriptor, so the docs table cannot drift from either side.
    """
    schema = a2a_schema.load_schema()
    descriptor = descriptor if descriptor is not None else build_catalog_cards(mission="ship-it")
    errors = a2a_schema.schema_errors(descriptor, schema=schema)
    card_fields = schema.messages["AgentCard"].fields
    rows = []
    for f in card_fields:
        if f.json_name in descriptor:
            bad = [e for e in errors if e.startswith((f"$.{f.json_name}.", f"$.{f.json_name}:",
                                                      f"$.{f.json_name}["))]
            status = "present, invalid" if bad else "present, valid"
        else:
            status = "missing"
        rows.append((f.json_name, "yes" if f.required else "no", status,
                     PROJECTION_SOURCES[f.json_name]))
    known = {f.json_name for f in card_fields} | {f.name for f in card_fields}
    extra = [(key, "unknown field", DESCRIPTOR_ONLY_SOURCES[key])
             for key in descriptor if key not in known]
    return rows, extra


def render_comparison(rows, extra):
    lines = ["| AgentCard field | Required | Offline descriptor | `--standard-card` source |",
             "|---|---|---|---|"]
    lines += [f"| `{f}` | {req} | {status} | {src} |" for f, req, status, src in rows]
    lines += ["", "| Descriptor key | In `lf.a2a.v1.AgentCard` | `--standard-card` destination |",
              "|---|---|---|"]
    lines += [f"| `{k}` | {status} | {dest} |" for k, status, dest in extra]
    return lines


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="a2a_export.py",
        description="Export open-fleet missions as offline mission descriptors "
                    "(format tag a2a-agent-card/v1, not an A2A AgentCard), or project a "
                    "validated lf.a2a.v1 AgentCard for an endpoint you operate.",
    )
    parser.add_argument("--mission", default=None, help="Export a single mission by name.")
    parser.add_argument("--skills-dir", default=str(SKILLS_DIR), help="Path to skills/ directory.")
    parser.add_argument("--doors", default=str(DOORS_PATH), help="Path to runtime/one-way-doors.json.")
    parser.add_argument("--out", default=None, help="Write JSON output to file instead of stdout.")
    parser.add_argument("--check", action="store_true", help="Validate export across all missions.")
    parser.add_argument("--compare", action="store_true",
                        help="Print lf.a2a.v1 AgentCard fields against the offline descriptor.")
    parser.add_argument("--standard-card", action="store_true",
                        help="Emit a validated lf.a2a.v1 AgentCard for --endpoint.")
    parser.add_argument("--endpoint", default=None,
                        help="The A2A endpoint you operate (required by --standard-card).")
    parser.add_argument("--binding", default=None, choices=STANDARD_BINDINGS,
                        help="Protocol binding served at --endpoint (required by --standard-card).")
    parser.add_argument("--protocol-version", default=None,
                        help="A2A protocol version served at --endpoint (default 1.0).")
    parser.add_argument("--agent-version", default=None,
                        help="AgentCard version (default: .claude-plugin/plugin.json version).")
    ns = parser.parse_args(argv)
    projection_flags = [flag for flag, value in (
        ("--endpoint", ns.endpoint), ("--binding", ns.binding),
        ("--protocol-version", ns.protocol_version), ("--agent-version", ns.agent_version),
    ) if value is not None]
    if ns.standard_card:
        if ns.endpoint is None or ns.binding is None:
            parser.error("--standard-card requires --endpoint and --binding: open-fleet serves "
                         "no A2A endpoint, so it never supplies or invents one")
        if ns.compare:
            parser.error("--compare describes the offline descriptor; drop --standard-card")
    elif projection_flags:
        parser.error(f"{', '.join(projection_flags)}: valid only with --standard-card")
    return ns


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    try:
        if ns.standard_card:
            payload = build_standard_card(
                ns.endpoint, ns.binding, protocol_version=ns.protocol_version or "1.0",
                agent_version=ns.agent_version, mission=ns.mission,
                skills_dir=ns.skills_dir, doors_path=ns.doors,
            )
        else:
            payload = build_catalog_cards(
                skills_dir=ns.skills_dir,
                doors_path=ns.doors,
                mission=ns.mission,
            )
        if ns.check or ns.compare:
            pin_problems = a2a_schema.pin_errors()
            if pin_problems:
                raise ExportError(f"vendored A2A schema drifted: {pin_problems}")
    except (ExportError, a2a_schema.ProtoSchemaError) as exc:
        print(f"a2a_export: FAILED: {exc}", file=sys.stderr)
        return 1

    if ns.compare:
        descriptor = payload if ns.mission else payload["cards"][0]
        print("\n".join(render_comparison(*field_comparison(descriptor))))
        return 0

    if ns.check:
        if ns.standard_card:
            print(f"A2A_STANDARD_CARD=ok skills={len(payload['skills'])}")
        else:
            count = 1 if ns.mission else payload["count"]
            print(f"A2A_EXPORT=ok cards={count} kind={DESCRIPTOR_KIND}")
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
