# Run report — <mission> <self-run | external-run>, <YYYY-MM-DD>

Every mission run fills this report in the **target project**, with evidence in its own
`docs/runs/<YYYY-MM-DD>-<mission>-<self-run|external-run>/` directory. Copy the template to
`docs/runs/<YYYY-MM-DD>-<mission>-<self-run|external-run>.md` and fill every applicable section;
explain any inapplicable section. Recording a run does not advance the catalog's proof tier.
Use `tier=doctrine-only` unless the separate **Catalog proof promotion** procedure below passes.

Run commands from the target project's Git root. In a source-clone install, set
`OPEN_FLEET_ROOT` to the absolute catalog clone; in a copied install, use the absolute mission
directory containing `SKILL.md`. Runtime invocations below already name
`"$OPEN_FLEET_ROOT/runtime/scripts/<file>"`; project commands, manifests, contracts, reports, and
artifact paths stay relative to the target project. Protocol names resolve through the installed
`references/README.md` index (or the catalog's playbooks/runtime directories for a source install).

Record exactly one `RUN:` header: mission, tier, the target-project evidence commit as
`inventory_at`, the manifest in this run's own artifact directory, the actual verifier
outcome, and the number of dispatch waves the run ran as `waves`. Keep a RED result as RED; it cannot certify completion. A coordinator independently
checks the manifest under `evidence-manifest` before a unit advances. If artifacts remain
uncommitted, record that explicitly in **Evidence binding**, use `inventory_at=uncommitted`,
and retain a content-hashed archive location; do not invent a commit or claim proof promotion.

```
RUN: mission=<mission> tier=<doctrine-only|self-run|external-run> inventory_at=<commit> manifest=docs/runs/<YYYY-MM-DD>-<mission>…/<manifest>.json verifier=<GREEN|RED> waves=<n>
```

| Field | Value |
|---|---|
| Mission | `<mission>` — mission source revision `<sha>` and installed location `<path>` |
| Tier claimed | `doctrine-only` unless catalog promotion passes; run kind: `self-run` (catalog) / `external-run` (other project) |
| Target | `<repo, surface, PR, or tracker>` |
| Fixed point | BASE `<branch>` @ `<sha>` · FORK_POINT `<sha>` · frozen spec / issue list `<ref + digest>` |
| Coordinator / workers | `<host + model>` · worker profiles `PROFILE=<ro or rw>` · TASK pack `<matt or addy>` |
| Orca | `orca status --json` → `runtime.reachable: true` at `<time>` (paste the line) |
| Human gates | `<gate>` — `<who>` @ `<time>` — `<decision>` |

## Terminal state

The mission's named terminal (from its `## Two terminal outcomes` section, degradation marker
included when one applies) and the ledger rows that show it, in the mission's canonical row shape:

`| task_id | unit | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | WT_CLEAN | lighting | park | evidence |`

## Convergence proof

Every clause of the mission's `## Convergence proof`, each with the evidence that discharges it:
a file path, a command with its exit code, or a PR url with its `reviewed_sha`.

## Pipeline evidence (per phase)

| Phase | Command / action | Result | Evidence |
|---|---|---|---|
| `<PHASE>` | `<command>` | `<exit code / verdict>` | `<path or url>` |

## Verifier outcome (recorded exactly)

Record the real verifier invocation through the installed recorder, using the SAME manifest:

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/evidence-run.py" --label verifier --manifest <manifest> --artifact <run-dir>/verifier.txt -- python3 "$OPEN_FLEET_ROOT/runtime/scripts/verify.py" --manifest <manifest> --contract-source <contract-source> --contract-digest <contract-digest> --unit-class <unit-class>`

Paste output and exit code verbatim, RED runs included. Append the dispatch's lane flags to the
verifier command: `--lighting`, `--dispatch-record`, `--dispatch-pubkey`, and integration `--base`
as applicable. Mutation units also follow build-change's negative-control invocation, including
`--execute-nc --nc-command '<coordinator-supplied command>'` when required by the lane; never
invent a review or select a waiver to make the run green. Keep unfulfilled gates pending.

Where each flag comes from: `--contract-source` is the coordinator's frozen contract from the Fixed point
row, supplied out of band (`ORCA_CONTRACT_SOURCE` under `verify-gate.sh`); `--contract-digest` and
`--unit-class` are the signed dispatch record's `contract_digest` and `unit_class` — always pass both,
since a missing unit class fails safe to mutation-strict checks; `--lighting` is the record's optional
`lighting` — when the record signs it, always pass its exact value (a signed `dark-eligible` passed as
nothing loses the review waiver and goes RED) **and** make sure the unit's manifest carries the same
`lighting` value: the verifier reads an omitted manifest lighting as `lit` and reports a fatal
`lighting swap` against a `dark-eligible` dispatch; when the record omits it, omit the flag. Omitting
the CLI flag does not populate the dispatch lighting, and with `--dispatch-record` a value the record
did not sign is a fail-closed RED. `--base` is the integration base for ancestry. Omitting the contract
flags is a fail-closed scope RED to record, not a flag to drop. `evidence-manifest` and
`gate-classification` are the mandatory protocols for these semantics.

## WIP-curve protocol row (mutating self-runs)

Required by `attention-budget` for every mutating self-run in the catalog; for external runs
and report-only missions, record why this self-run measurement is inapplicable.

One row per dispatch wave, `wave=1` … `wave=<n>` for the `RUN:` header's `waves=<n>`, each
carrying every labeled cell below with a digit-led measured value (whole numbers for `wave`,
`builders`, `reviewers`). `run_report.py` refuses a row whose labeled cell is missing, unmeasured
or written twice — a bare value without its `key=` label counts as missing; other cells, such as a
note, are free. The two rows show a two-wave run — add or delete rows to match.

| Wave | WIP setting | Builder throughput | Verification latency | Rework rate | Freshness violations |
|---|---|---|---|---|---|
| `wave=1` | `builders=<n> reviewers=<n>` | `throughput=<v>` | `latency_median=<v> latency_max=<v>` | `rework=<v>` | `freshness=<v>` |
| `wave=2` | `builders=<n> reviewers=<n>` | `throughput=<v>` | `latency_median=<v> latency_max=<v>` | `rework=<v>` | `freshness=<v>` |

## Deviations and lessons (recorded, not hidden)

- `<what the run did differently from the SKILL, and why>`

## Run-close integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `<file>` | `<digest>` | `<tool + version, date>` |

List the manifest and every artifact owned by this run, with producer and timestamp. After the
last recorded command, freeze those bytes and fill the hashes (do not include the report itself):

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/inventory.py" write <report>`

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/inventory.py" check <report>`

Require zero mismatches, at least one verified path, and no missing run-owned artifact; an exit
of zero alone is insufficient because historical missing paths are reported separately. Retain
all run-owned evidence, including the graded manifest, in the target project's evidence commit;
put that SHA in `inventory_at` and recheck its inventory with:

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/inventory.py" check <report> --at <inventory_at>`

Do not rewrite earlier command commit/tree observations to match the later evidence commit.
If project policy keeps evidence outside Git, name the durable archive and its integrity inventory
in **Evidence binding**, re-hash it, and keep the catalog at doctrine-only. Report any unmet
retention requirement as pending, never as a successful gate.

## Gates

Run the target project's required validation/build/lint and test commands at the final
implementation head, using its documented CI/acceptance contract to select them. Fill these
placeholders with real project commands, record exact output and exits, and require success:

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/evidence-run.py" --label validation --manifest <manifest> --artifact <run-dir>/validation.txt -- <project-validation-command>`

`python3 "$OPEN_FLEET_ROOT/runtime/scripts/evidence-run.py" --label tests --manifest <manifest> --artifact <run-dir>/tests.txt -- <project-test-command>`

A help invocation or an empty test collection does not satisfy these gates. Run the verifier
above with the coordinator's authoritative inputs; finish the inventory after recording all
gates. An external project uses its own validation/test tools, without requiring a catalog layout.

## Catalog proof promotion

This additional procedure applies only when maintaining or promoting proof in the **open-fleet
catalog**. It is not a prerequisite for recording an external project's run. Preserve the original
project evidence and its verifier outcome; a copied installation's receipt alone does not meet
the catalog's repository-verifier binding rule. Catalog maintainers must satisfy that binding
with an actual catalog verifier execution and its authoritative inputs, or keep doctrine-only.

Copy this file to `docs/runs/<YYYY-MM-DD>-<mission>-<self-run|external-run>.md`, fill every
section, add the row to the index table in `docs/runs/README.md`, then set the mission's
`metadata.proof:` and `metadata.proof_evidence:` to the new path.

Nothing else advances a catalog tier, and naming the mission is not enough (issue #259).
`"$OPEN_FLEET_ROOT/runtime/scripts/run_report.py"`, called from `scripts/validate.py`, requires all of:

* the `RUN:` header above, exactly once, with every field;
* `inventory_at=` a commit that exists **in this repository**;
* `manifest=` a path that exists at that commit and lives inside this run's own
  `docs/runs/<YYYY-MM-DD>-<mission>…/` artifact directory — borrowing another run's manifest is
  refused;
* `verifier=GREEN|RED` matching what the "Verifier outcome" section records (a RED is honest: a
  solo run cannot manufacture an independent approver) — and the body must show the ACTUAL
  invocation, `verify.py … --manifest <that same manifest path>`, not a description of it. Paste
  the command and its exit code; a sentence about having run it is not a transcript;
* the integrity inventory re-hashing at `inventory_at` — zero mismatches, at least one verified
  path inside this run's own directory, **the graded manifest among the hashed paths**, and none
  of this run's own artifacts absent there. Paths outside the run directory may have moved on;
  the evidence the run is responsible for may not.

If your artifacts are not committed here, this report is recorded history and the mission stays
`doctrine-only`. Say that in an "Evidence binding" section rather than claiming a tier.

These are additional catalog gates, run from the catalog clone at its final head, with exact
output and exits (the generic project validation/test and evidence requirements above still apply):

`python3 scripts/validate.py`, `python3 -m unittest discover -s tests`, and
`python3 "$OPEN_FLEET_ROOT/runtime/scripts/proof_status.py" --check`.
