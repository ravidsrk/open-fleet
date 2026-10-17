"""Wire the regenerated images into the docs: light/dark <picture> embeds, new embeds, contract alt text.

ARCHITECTURE.md is deliberately left alone: it is a root doc every mission's activation load counts, and an
image block there costs every coordinator ~200 tokens per run for a picture no agent can see."""
import pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import specs  # noqa: E402

REPO = pathlib.Path([a for a in sys.argv[1:] if not a.startswith("--")][0])
CONTRACT = {s["id"]: s["contract"] for s in specs.MISSIONS}

def mission_alt(mid):
    c = CONTRACT[mid]
    states = " or ".join(c["states"])
    tidy = lambda t: t.replace(" · ", "; ").replace(" → ", ", ")
    return (f"Mission contract for {mid}: you give it {tidy(c['give'])}; it interrupts you for "
            f"{tidy(c['gates'])}; you get back {states}, plus {tidy(c['artifacts'])}; it stops at "
            f"{tidy(c['stops'])}; phases {tidy(c['phases'])}")

NEW_ALT = {
 "you-say": "Three columns, what you say, what the fleet runs, what you get: ship this becomes freeze, build, review and PROMOTION_READY with evidence; close every issue becomes triage, fix, re-enumerate and a backlog at zero, SHA-linked; harden this becomes audit, exploit, re-attack and a CLEAN re-audit or named gaps; why is this flaky becomes reproduce, falsify, prove and a demonstrated root cause",
 "negative-control": "Head-to-head on the same gamed manifest that reports only AC-1 of a two-criterion spec: a self-scoring gate grades the worker's own list and returns GREEN; orca-fleet's verifier re-derives the criterion set from the frozen spec in a fresh session and returns RED, AC-2 not addressed; and for every fix the negative control reverts it and the proof must go RED",
 "install-stack": "The stack, bottom to top: the Orca app with orchestration enabled, the orca CLI, the orchestration and orca-cli skills, the orca-fleet missions, and the upstream packs, one per worker; three install paths: a symlink with the completion gate off until the settings snippet is wired, the Claude Code plugin with the gate on by construction, and the skills CLI, which severs playbook references and is not supported today",
 "gates-terminal": "A freeze decision as it reaches your terminal: two options with one recommended, reply a or b, no timeout default because the freeze is a one-way gate; beside it a taste gate that takes the recommendation and keeps working for your later veto, and the promotion PR the fleet opens and leaves for you to merge",
 "artifacts-map": "What a run leaves behind: a ledger with one row per unit; a docs/runs directory holding the report, a manifest per unit and a sha256 inventory; one PR per unit merged into BASE with reviewed_sha equal to head; and a promotion PR from BASE to default left to you",
 "mission-handoffs": "How missions hand off: map-it to ship-it with a frozen map and DAG; root-cause to ship-it or clean-sweep with a fix handoff brief; modernize-it and ship-it to migrate-it for stateful changes; deflake-it and prove-it to clean-sweep for deterministic and surfaced bugs; attest-it to ship-it for remediation; oncall-it to root-cause for telemetry; and a chain harden-it, prove-it, ship-it gated by each verified terminal",
 "proof-ladder": "The proof ladder: doctrine-only, then self-run, then external-run; advancing needs a run report that binds, with a RUN header, a manifest in the run's own directory and an inventory that re-hashes at the named commit; the live state is the archive at docs/runs/README.md, which names each mission's tier as its evidence lands",
 "verify-gate": "The completion gate: the coordinator sets the gate env, a Stop or TaskCompleted hook fires verify-gate.sh, verify.py re-derives scope and review and reads the negative control, replaying it in a throwaway worktree only when ORCA_EXECUTE_NC is set, then exit 0 allows or exit 2 blocks, fail-closed; the verdict is advisory inside the worker's own session and sound where CI, MCP-Task or an SDK subprocess owns the env",
 "mission-identity": "The six-point mission-identity test: unit of work, per-unit state machine, convergence proof, ordering and isolation, parking and failure semantics, and the oracle; audit findings, tracker issues and doc claims are one mission, clean-sweep, while a perf breach is a different proof and therefore a different mission, speed-it",
 "threat-boundaries": "The four security boundaries from threat-model.md — sandbox with isolated worktree, ro/rw/danger profiles, PreToolUse deny-hook and v1.4.229 OS process/memory ceiling; network with hash-chained egress.py receipts; supply chain with runtime/pins.json, pin_review.py rug-pull audit, one pack per worker and guard_text.py trust envelope; identity and access with ed25519 dispatch-sign.py contract digest, human-only one-way gates and an independent SHA-bound verifier — beside the five-rung response ladder from steer, reduce and stop to revoke and fail-closed quarantine",
 "tracker-enumeration": "Four-stage pipeline for hosted trackers: GitHub Issues/PRs, Linear via orca linear, and Jira via orca jira at v1.4.229 enter the T0 twin-query denominator paged until truncated is false and reconciled across two independent workers, pass through the guard_text.py trust fence so ticket text remains data rather than authority, and close with single-attempt writeId or read-back plus orca reference add/find backed by a verified merge SHA",
}

def picture(prefix, name, alt, width):
    dark = f"{prefix}assets/diagrams/{name}.jpg"; light = f"{prefix}assets/diagrams/{name}-light.jpg"
    return ('<p align="center">\n  <picture>\n'
            f'    <source media="(prefers-color-scheme: dark)" srcset="{dark}">\n'
            f'    <source media="(prefers-color-scheme: light)" srcset="{light}">\n'
            f'    <img src="{light}" alt="{alt}" width="{width}">\n'
            '  </picture>\n</p>')

IMG = re.compile(r'<p align="center">\n  <img src="((?:\.\./)*)assets/diagrams/([A-Za-z0-9/_-]+)\.jpg" alt="([^"]*)" width="(\d+)">\n</p>')
PIC = re.compile(r'<p align="center">\n  <picture>\n    <source media="\(prefers-color-scheme: dark\)" srcset="((?:\.\./)*)assets/diagrams/([A-Za-z0-9/_-]+)\.jpg">\n'
                 r'    <source media="\(prefers-color-scheme: light\)" srcset="[^"]*">\n    <img src="[^"]*" alt="([^"]*)" width="(\d+)">\n  </picture>\n</p>')

def _alt_for(name, alt):
    base = name.split("/")[-1]
    if name.startswith("missions/") and base in CONTRACT:
        return mission_alt(base)
    return NEW_ALT.get(base, alt)

def convert_existing(text):
    """Turn bare <img> embeds into picture blocks and refresh the alt text of blocks that already exist."""
    def rep(m):
        prefix, name, alt, width = m.groups()
        return picture(prefix, name, _alt_for(name, alt), width)
    return PIC.sub(rep, IMG.sub(rep, text))

def _has(text, block):
    dark = re.search(r'srcset="([^"]+\.jpg)"', block).group(1)
    return dark in text

def _anchor_re(anchor):
    # A heading anchor is the whole line: `## Proof status` must not be satisfied by
    # `## Proof status — details` (PR #398 review). A prose anchor is an exact substring.
    if anchor.startswith("#"):
        return re.compile(r"^" + re.escape(anchor) + r"[ \t]*$", re.M)
    return re.compile(re.escape(anchor))

def _anchored(text, anchor, doc):
    # Checked on every run, not only when the picture is missing: a committed embed used to hide a
    # renamed heading until the next regeneration asserted on it (PR #387 review).
    hits = len(_anchor_re(anchor).findall(text))
    assert hits == 1, (doc, anchor[:60], hits)

def insert_after(text, anchor, block, doc):
    _anchored(text, anchor, doc)
    if _has(text, block):
        return text
    return _anchor_re(anchor).sub(lambda m: m.group(0) + "\n\n" + block, text, count=1)

def insert_before(text, anchor, block, doc):
    _anchored(text, anchor, doc)
    if _has(text, block):
        return text
    return _anchor_re(anchor).sub(lambda m: block + "\n\n" + m.group(0), text, count=1)

DRY = "--dry-run" in sys.argv

def edit(path, fn):  # idempotent: a rerun refreshes alt text and inserts only what is missing
    p = REPO / path; t = p.read_text(); n = fn(t)
    if n == t:
        print(f"unchanged {path}")
        return
    before, after = t.count("<img "), n.count("<img ")
    pics = n.count("<picture>")
    if not DRY:
        p.write_text(n)
    print(f"{'would wire' if DRY else 'wired'} {path}: img {before}->{after}, picture blocks {pics}")

# --- README -------------------------------------------------------------------------
def readme(t):
    t = convert_existing(t)
    _anchored(t, "```\n YOU SAY", "README")
    if "assets/diagrams/you-say.jpg" not in t:
        ascii_start = t.index("```\n YOU SAY")
        ascii_end = t.index("```\n", ascii_start + 4) + 4
        ascii = t[ascii_start:ascii_end].rstrip("\n")
        t = (t[:ascii_start] + picture("", "you-say", NEW_ALT["you-say"], 1000) + "\n\n"
             "<details>\n<summary>Text version</summary>\n\n" + ascii + "\n\n</details>\n" + t[ascii_end:])
    # The README's intro sentences are prose now; each picture sits right after its own.
    t = insert_after(t, "Missions also hand work to one another, each handoff a separately authorized run:",
        picture("", "mission-handoffs", NEW_ALT["mission-handoffs"], 900), "README")
    t = insert_after(t, "([demo/negative-control/](demo/negative-control/README.md)):",
        picture("", "negative-control", NEW_ALT["negative-control"], 900), "README")
    t = insert_after(t, "## Proof status",
        picture("", "proof-ladder", NEW_ALT["proof-ladder"], 900), "README")
    t = insert_after(t, "## Requirements",
        picture("", "install-stack", NEW_ALT["install-stack"], 900), "README")
    return t

def concepts(t):
    t = convert_existing(t)
    t = insert_before(t, "A unit that fails any required check is not done",
        picture("../", "negative-control", NEW_ALT["negative-control"], 820), "concepts")
    t = insert_after(t, "## Security boundaries and the response ladder",
        picture("../", "threat-boundaries", NEW_ALT["threat-boundaries"], 820), "concepts")
    t = insert_after(t, "## Hosted trackers and the trust envelope",
        picture("../", "tracker-enumeration", NEW_ALT["tracker-enumeration"], 820), "concepts")
    t = insert_after(t, "## Proof status", picture("../", "proof-ladder", NEW_ALT["proof-ladder"], 820), "concepts")
    t = insert_after(t, "## The mission-identity test",
        picture("../", "mission-identity", NEW_ALT["mission-identity"], 820), "concepts")
    return t

def getting_started(t):
    t = convert_existing(t)
    t = insert_after(t, "## Prerequisites", picture("../", "install-stack", NEW_ALT["install-stack"], 820), "getting-started")
    t = insert_after(t, "## Where the evidence lands", picture("../", "artifacts-map", NEW_ALT["artifacts-map"], 820), "getting-started")
    t = insert_after(t, "## Your side of the human gates", picture("../", "gates-terminal", NEW_ALT["gates-terminal"], 820), "getting-started")
    return t

def verify_gate(t):
    t = convert_existing(t)
    return insert_before(t, "## Install paths, and which ones carry the gate",
        picture("../", "verify-gate", NEW_ALT["verify-gate"], 820), "verify-gate")

def missions_index(t):
    t = convert_existing(t)
    return insert_before(t, "| Guide | One line |",
        "How the missions hand work to one another:\n\n" + picture("../../", "mission-handoffs", NEW_ALT["mission-handoffs"], 820),
        "missions/README")

edit("README.md", readme)
edit("docs/concepts.md", concepts)
edit("docs/getting-started.md", getting_started)
edit("docs/verify-gate.md", verify_gate)
edit("docs/missions/README.md", missions_index)
edit("docs/guides/anatomy-of-a-run.md", convert_existing)
for mid in CONTRACT:
    edit(f"docs/missions/{mid}.md", convert_existing)
print("done")
