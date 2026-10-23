# Playbook — doc-coverage  (extract the public surface, map it by quadrant, prove the gaps)

Recipe: gstack `document-release` (coverage map as an audit lens, diagram drift, CHANGELOG/VERSION
rules) + `document-generate` (Diataxis partition, reference-first, code archaeology). The unit is
ONE (public-surface entity × quadrant) cell. This playbook produces the MAP and verifies the
CLAIMS; it does not write the prose — it hands each gap to a writer unit and checks what comes
back. `document-it` runs it over a whole surface; `release.md`'s doc-sync unit runs it over one
wave's diff.

## 1. Extract the surface with a script, not a reading

The denominator is machine-derived at a named base SHA and re-derivable by a verifier: exported
symbols, CLI commands and flags, config keys and environment variables, HTTP routes, published
skills or plugins, feature flags. Write the extractor into the repo (or name the existing one),
paste its output and its command, and record the SHA. A hand-listed surface is a claim, and it
shrinks silently as the code grows. Extraction is per-language and is the hard part: where a
language or framework has no reliable extractor, that sub-surface is PARKED as unextractable with
the attempt recorded — never quietly dropped from the denominator.

## 2. Map coverage by grep-able evidence, per quadrant

Four quadrants, each defined by what it answers, each scored only by a `file:line` a grep found:

| Quadrant | Answers | Typical home |
|---|---|---|
| reference | what it is, its options, its types and defaults | README tables, API docs, AGENTS |
| how-to | how do I accomplish task X with it | guides, CONTRIBUTING workflows |
| tutorial | zero → working example for a newcomer | getting-started |
| explanation | why it works this way, what was traded | architecture docs, ADRs |

```
entity            reference   how-to   tutorial   explanation
--path-filter     README:88   ✅ #run   ❌         ❌
FooProcessor      ❌          ❌       ❌         ❌      ← critical gap
```

**Critical gap** = zero coverage in any quadrant. **Common gap** = reference-only. Not every entity
merits all four: an internal module needs reference + explanation, a flag needs reference + how-to.
Which entities merit a tutorial or an explanation is a human's call, taken once, on the frozen list.

## 3. Cross-reference the diagrams

Extract entity names from every ASCII or Mermaid diagram in the docs and match them against the
extracted surface. A diagram naming a module that was renamed, split, or deleted is a gap of its
own. Diagram repair is advisory here — flag it, hand it to a human or a writer unit; never
auto-rewrite art whose meaning is a judgment.

## 4. Discoverability is part of coverage

A doc no path leads to is not coverage. Every landed doc must be reachable from the repo's root
entry points (README / the agent-facing index) in one hop, and the map records the inbound link.
An orphan page is a gap even when its content is perfect.

## 5. Claim verification (the doc-claims oracle)

Every factual claim in a landed doc binds to an anchor: a `file:symbol`, a config key, or a pasted
command run with its output. The check is mechanical and re-runnable, and it has a negative
control: rename the anchored fact on a throwaway branch and the claim check must go RED. A claim
that cannot be anchored is either removed or marked as design rationale owned by a human
(`explanation-needs-author`) — it is never shipped as a fact.

## 6. Rules that protect what already exists

- **Never clobber the changelog.** Polish wording; never delete, replace, or regenerate entries.
- **Never bump the version silently.** The bump is a separate, asked decision.
- **Never delete an ADR or a superseded doc** — supersede it and link forward.
- **Read the whole file before editing it**, and match the repo's existing conventions (directory,
  naming, front matter, voice) instead of importing another project's.
- **Reference before how-to and tutorial** for the same entity: reference establishes the
  vocabulary the other quadrants use, and it is the quadrant derivable from code alone.
- **The map informs; it does not generate.** Filling a cell is a writer unit's job with its own
  review; this playbook flags, orders, and verifies.

## Completion

The extractor's command, output, and base SHA are in the ledger; every extracted entity has a row;
every scored cell cites a `file:line`; critical and common gaps are separated and the frozen gap
list is human-bounded; diagram entities cross-reference clean or are flagged; every landed doc is
reachable in one hop; every claim in a landed doc has a verified anchor and the rename negative
control went RED; the changelog is unclobbered and no version moved without an explicit decision.
