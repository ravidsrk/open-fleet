# Platform-ride architecture & absorption-risk register

*How orca-fleet builds on the Claude Code / Agent SDK / MCP substrate: ride the native primitives
for topology and isolation, keep the verification + ops-hardening layer as the differentiator.*

> Companion to [`docs/research/2026-08-28-forward-roadmap-and-defensibility-plan.md`](research/2026-08-28-forward-roadmap-and-defensibility-plan.md).
> The platform is a moving target; every row is a dated snapshot (2026-08-28), not a standing contract.

## The principle

The letters are the four defensibility claims of the
[competitive-landscape snapshot](research/2026-08-28-competitive-landscape-differentiation.md):
**A** an outcome commitment with a per-unit state machine and a convergence proof; **B** the
evidence protocol (SHA-bound manifest, independent second-session verifier, negative control,
frozen denominator); **C** the coordinator/worker topology; **D** the operational hardening
(merge-train serialization, reviewed-SHA freshness, attention budget, liveness-resume, one router
per worker).

The substrate is absorbing **claim C** (coordinator/worker topology) and the isolation slice of
**claim D** right now, and it ships **no completion oracle**. So the durable value is **claim B**
(a SHA-bound evidence manifest + an independent second-session verifier that re-derives from git,
with a mandatory negative control and a frozen denominator) plus the rest of **D** (merge-train
serialization, reviewed-SHA freshness, attention budget, liveness-resume, one-router-per-worker).

**Rule of thumb:** if Anthropic ships it as a primitive, ride it — never reimplement it. Spend the
budget on B + D, which the platform does not provide.

## Ride vs. keep

| orca-fleet concept | Native primitive to ride | Keep as the differentiator |
|---|---|---|
| Coordinator + workers | agent teams: **lead + teammates**, shared task list (deps + file-lock claim), plan-first | coordinator-**never-writes-code** discipline; single **merge conductor** |
| Isolated worker | subagents with **`isolation: worktree`** (enforced) | — (isolation is free now) |
| Build-blind reviewer | **read-only subagent** (`tools: Read, Grep, Glob`; built-in Explore/Plan deny writes) | reviewer-mode independence checks ([evidence manifest §2](../runtime/evidence-manifest.md#2-independent-verification-the-coordinator-or-a-fresh-verifier-worker)) |
| Serialization substrate | shared task list (dependency unblock + file-lock claim) | merge-train ordering + hot-file chains |
| Independent verifier | **headless Agent SDK / `claude -p`** run (teammates do *not* spawn in `-p`, so it is naturally a lone, separate session) or an **MCP Task** | the re-derivation *content*: `merge-base --is-ancestor`, clean-env test at the SHA, `reviewed_sha == head_sha`, **negative control**, **frozen denominator** |
| Completion gate | plugin **`Stop` + `TaskCompleted`** hooks (exit 2 → block completion + feedback) | what the gate *checks* (the manifest), not that a gate exists |
| Attention budget | **`TeammateIdle`** hook (exit 2 → keep a teammate working) | the reviewer/builder ratio policy |
| Evidence freshness | MCP **ETag / content-versioning** (roadmap, 6–12mo) | the ledger was never the moat; negative control + frozen denominator are |
| Per-worker credentials | MCP **agent-identity / delegation** (roadmap) | one-router-per-worker + sandbox profiles; attest the verifier as a distinct principal |
| Workspace tracker links & agent lookup | **`orca reference list\|add\|remove\|find`** + **`orca agent launch --retry-launch`** (Orca v1.4.229) | T0 twin-query denominator + single-attempt write verification (`linear-enumeration.md`) |
| Per-terminal resource ceiling | **`ORCA_TERMINAL_PROCESS_CEILING`** + **`ORCA_TERMINAL_MEMORY_MAX`** cgroup/Job limits on `orca serve` (Orca v1.4.229) | fail-closed PreToolUse deny-hook + `ro`/`rw`/`danger` profiles (`sandbox-policy.md`) |
| Agent-readable CLI diagnostics | structured JSON + non-interactive error contracts (`gstack` CAP4/CAP6 DX contract) | fail-closed exit codes (`0`/`2`/`3`) with machine-parseable refusal codes (`verify.py`, `guard_text.py`) |

**Load-bearing move:** run the verifier as a *different session/process*, **never as a teammate** —
teammate/cross-session messages are in-band and self-certifying, which is exactly the trace-as-oracle
failure the evidence protocol rejects.

## Absorption-risk register (2026-08-28, refreshed 2026-10-17)

Status: **SHIPPED** (live) · **ANNOUNCED** (public roadmap) · **SPECULATED** (inference).

| # | Risk | Status / horizon | Mitigation |
|---|---|---|---|
| R1 | Agent-teams **GA** absorbs coordinator + workers + shared task list → claim C fully commoditized | SPECULATED, GA <6–18mo | Ride it; move value to B + D |
| R2 | Native read-only subagents + `isolation: worktree` already commoditize build-blind + isolation | SHIPPED, now | Keep coordinator-never-writes + single conductor + rest of D |
| R3 | `Stop`/`TaskCompleted` hooks make quality gates a **generic** surface (anyone ships a Stop-hook gate) | SHIPPED, now | Differentiate on B's *content*; prove it with the negative-control demo (#73) |
| R4 | `allowManagedHooksOnly` + plugin-subagent hook limits lock plugin gates out of managed/enterprise | SHIPPED, now | Ship the gate ALSO as an MCP Task / CI gate / SDK subprocess (#77) |
| R5 | agentskills.io standardizes an outcome/verification `metadata` vocabulary | SPECULATED, not on roadmap | Own the runtime behavior, not the metadata; keep `proof:` free-form |
| R6 | Agent SDK / Managed-Agents **advisor** becomes a git-grounded completion gate | SPECULATED | Watch; independent-session + negative control remain the differentiator |
| R7 | MCP **ETag + Tasks** make SHA-bound evidence *ledgers* trivial | ANNOUNCED, 6–12mo | Ledger was never the moat; ride the primitive |
| R8 | Orca v1.4.229 ships native **`orca jira`**, **`orca reference`**, **`orca agent launch`**, and **`orca serve` systemd/Job ceilings** | SHIPPED, 2026-10-17 | Ride all four as substrate (`linear-enumeration.md`, `dispatch-lifecycle.md`, `sandbox-policy.md`); keep T0 twin-query denominator + SHA-bound merge verification |

## Signals watch-list

Track these dated artifacts; a change here is a threat signal (see the threat brief for detail):

- **Ruflo (claude-flow)** — `ruvnet/ruflo` releases + ADR index: watch Witness Verification (ADR-103)
  moving from install-integrity toward a **per-task completion** manifest, and any **negative control**
  or **frozen-denominator** addition to the Truth Verification / PAIR navigator.
- **Octomind** — release notes: the "checklist-from-request" + "provenance bit" moving toward an
  independent, git-grounded, negative-controlled gate.
- **Factory.ai** — research/news: validator-workers or Droid Shield git-audit repurposed from
  *security* to *completion* verification.
- **Anthropic** — Claude Code changelog + Agent SDK: agent-teams GA; any first-class verification/eval
  step in the SDK or Managed-Agents advisor.
- **MCP** — roadmap/SEPs: Tasks (SEP-2663), ETag/versioning (SEP-2549), agent-identity WG.

## Sources

Primary sources (accessed 2026-08-28): Claude Code [agent teams](https://code.claude.com/docs/en/agent-teams),
[subagents](https://code.claude.com/docs/en/sub-agents), [hooks](https://code.claude.com/docs/en/hooks),
[plugins](https://code.claude.com/docs/en/plugins), [Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview);
[Managed Agents multiagent orchestration](https://platform.claude.com/docs/en/managed-agents/multiagent-orchestration);
[agentskills.io spec](https://agentskills.io/specification.md); [MCP roadmap](https://modelcontextprotocol.io/development/roadmap).
Full analysis in the [forward roadmap snapshot](research/2026-08-28-forward-roadmap-and-defensibility-plan.md).
