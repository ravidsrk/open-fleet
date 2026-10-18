# 2025–2026 Coding Agent Orchestration Space — Deep Research & Lessons for `orca-fleet`

> **Dated snapshot (2026-10-18).** Counts, tool surfaces, and external landscape comparisons below reflect the repository and ecosystem state on 2026-10-18; live doctrine lives in `ARCHITECTURE.md`, `playbooks/`, and `runtime/`.

**Date:** 2026-10-18
**Scope:** Multi-agent coding orchestration harnesses, protocols (`MCP`, `A2A`, `ACP`, `agentskills.io`), worktree swarms, execution-backed review engines, and verification architectures — and what `orca-fleet` implements from the findings.

---

## 1. Core Thesis

Across 2025–2026, the multi-agent software engineering ecosystem converged on a shared **execution substrate**—isolated git worktrees, subagent fan-out, a central task ledger, and a serialized merge queue—while diverging sharply on **how completion is proved** and **where governance lives**. Almost every framework in the market still grades completion on agent self-attestation or a green CI badge on the final commit. `orca-fleet`'s deepest moat is **verification-first, below-the-model orchestration**: SHA-bound evidence manifests re-derived in an independent git session ([`runtime/evidence-manifest.md`](../../runtime/evidence-manifest.md)), mandatory negative controls (`revert` / `mutmut` → RED), frozen $T_0$ denominators ([`playbooks/linear-enumeration.md`](../../playbooks/linear-enumeration.md)), one-way-door governance below the model ([`runtime/gate-classification.md`](../../runtime/gate-classification.md)), and a four-boundary runtime security envelope ([`runtime/threat-model.md`](../../runtime/threat-model.md)).

---

## 2. The 2026 Convergent Architecture

Independent orchestration systems—from terminal harnesses (`stablyai/orca`, Claude Code Subagents & Agent Teams, OpenAI Codex CLI) to cloud SWE platforms (Devin, Factory.ai Missions, OpenHands, Cursor Cloud) and community swarms (Gas Town, Composio Agent Orchestrator, `ccswarm`, `claude-flow`)—have converged on a five-part runtime topology:

1. **Protocol & Discovery Layer (`MCP` + `A2A` + `agentskills.io`):**
   - **MCP (Model Context Protocol)** won the vertical *agent-to-tool* integration layer.
   - **A2A (Agent2Agent Protocol)** and **ACP (OpenHands Agent Communication Protocol)** standardized horizontal *coordinator-to-agent* discovery via **Agent Cards** (capabilities, auth, input/output schemas) and lifecycle **Task Artifacts**.
   - **`agentskills.io` (`SKILL.md`)** standardized portable skill packaging across Claude Code, Cursor, Gemini CLI, Codex, and OpenCode.
2. **Coordinator & Authoritative Ledger:**
   - Natural-language chat history between peers is replaced by a state machine (`orca orchestration task-*`, Beads in Gas Town, SQLite DAGs in `claude-flow`) that owns task state (`pending` → `ready` → `dispatched` → `completed`), dependency unblocking, and retry counts.
3. **Physical Isolation via Git Worktrees & OS Sandboxes:**
   - Every concurrent worker runs in its own git worktree (`git worktree add`) and disposable container or OS cgroup ceiling (`ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX` in Orca `v1.4.229`) so filesystem edits and dependency installs never collide.
4. **Two-Speed Verification Harness:**
   - **Inner loop (inside the worker):** deterministic lint/type/test hooks ([`runtime/scripts/verify-gate.sh`](../../runtime/scripts/verify-gate.sh)) catch immediate syntax or regression errors and feed compact `stderr` back for bounded local repair.
   - **Outer loop (coordinator/verifier):** an independent session ([`runtime/scripts/verify.py`](../../runtime/scripts/verify.py)) re-derives git ancestry, runs the test suite in a clean environment, executes a negative control, and checks `reviewed_sha == head_sha`.
5. **Serialized Merge Train (`Refinery` / `Conductor`):**
   - Parallel branches never merge concurrently. A single merge queue ([`runtime/merge-serialization.md`](../../runtime/merge-serialization.md)) rebases each candidate onto `BASE`, checks whether the content tree changed (`git rev-parse HEAD^{tree}`), re-runs tests if needed, and merges.

---

## 3. Six Orchestration Archetypes Compared Against `orca-fleet`

| Archetype | Representative Systems (2025–2026) | Core Strength | Blind Spot / Failure Mode | How `orca-fleet` Compares |
| :--- | :--- | :--- | :--- | :--- |
| **1. Native CLI Harnesses & Subagents** | **Orca (`stablyai/orca`)**, **Claude Code Subagents & Agent Teams**, **OpenAI Codex CLI / App** | Low-latency local worktree isolation, native terminal lifecycle, worktree hooks, OS process/memory ceilings (`v1.4.229`). | Native subagents ship *primitives* (spawn, message, worktree), not outcome state machines or anti-cheat verification. | `orca-fleet` is the **mission, playbook, and verification layer** that rides on top of Orca's worktree/terminal primitives ([`ARCHITECTURE.md`](../../ARCHITECTURE.md)). |
| **2. Cloud Autonomous SWE Platforms** | **Devin 2.x**, **Factory.ai (Droids & Missions)**, **OpenHands Cloud**, **Cursor Cloud Agents**, **Google Jules** | Zero-setup ephemeral cloud VMs, browser/DB preview environments, Slack/Jira/Linear bots, long-horizon background execution. | Proprietary black-box workflows; completion is usually graded on a green PR check rather than a negative-control proof or independent git re-derivation. | [`skills/offload-it/SKILL.md`](../../skills/offload-it/SKILL.md) + [`runtime/sandbox-policy.md`](../../runtime/sandbox-policy.md) bring cloud-sandbox execution to open markdown missions while keeping SHA-bound verification. |
| **3. Single-Session Methodology Packs** | **`garrytan/gstack`**, **`mattpocock/skills`**, **`addyosmani/agent-skills`**, **`obra/superpowers`** | Battle-tested vertical craft: TDD loops, sprint role personas (`/review`, `/qa`, `/ship`), content-tree review freshness (`gstack-wtree`). | Designed primarily for a **single developer session**; co-mounting two packs in one worker causes router and TDD-philosophy collisions. | `orca-fleet` pins all three in [`runtime/pins.json`](../../runtime/pins.json), audits them via [`runtime/scripts/pin_review.py`](../../runtime/scripts/pin_review.py), and enforces **one pack per worker** ([`scripts/validate.py`](../../scripts/validate.py)). |
| **4. Community Worktree Swarms** | **Gas Town (`steveyegge/gastown`)**, **Composio Agent Orchestrator**, **`ccswarm`**, **`claude-flow`**, **Overstory** | High-throughput parallel worktree dispatch, Mayor/Polecat/Refinery merge queues, automatic CI-failure feedback routing. | **Zero supply-chain or prompt-injection containment**; workers read raw GitHub/Linear issues with full shell/network access and grade completion on worker self-report. | `orca-fleet` pairs worktree fan-out with [`runtime/scripts/guard_text.py`](../../runtime/scripts/guard_text.py), [`runtime/scripts/egress.py`](../../runtime/scripts/egress.py), [`runtime/scripts/dispatch-sign.py`](../../runtime/scripts/dispatch-sign.py), and [`runtime/scripts/verify.py`](../../runtime/scripts/verify.py). |
| **5. Execution-Backed PR Reviewers** | **Greptile (TREX)**, **CodeRabbit**, **Qodo Merge**, **Bugbot** | Whole-repo graph indexing plus disposable test execution (TREX) to validate review hypotheses before commenting. | Review-only (cannot orchestrate full backlog drains, DB migrations, or multi-unit refactors). | [`skills/review-it/SKILL.md`](../../skills/review-it/SKILL.md) + [`skills/absorb-it/SKILL.md`](../../skills/absorb-it/SKILL.md) run parallel build-blind `ro` lenses and bind `VERDICT: GO` to `reviewed_sha` via [`scripts/verdict_check.py`](../../scripts/verdict_check.py). |
| **6. General Multi-Agent Graph SDKs** | **LangGraph**, **Google ADK**, **OpenAI Agents SDK**, **Microsoft Agent Framework** | Durable checkpointing, typed state graphs, OpenTelemetry tracing, A2A/MCP adapters. | Domain-agnostic plumbing: zero built-in knowledge of git ancestry, worktrees, mutation testing, or software engineering missions. | `orca-fleet` encodes software engineering outcome state machines directly as validator-checked markdown + deterministic Python scripts. |

---

## 4. Concrete Lessons Adopted into `orca-fleet`

### Lesson 1: Pre-Dispatch Scope-Overlap Detection (`runtime/scripts/diff_scope.py --overlap`)
- **Problem in the field:** Serialized merge queues ([`runtime/merge-serialization.md`](../../runtime/merge-serialization.md)) prevent broken `BASE` branches, but when concurrent workers touch overlapping shared files (`package.json`, central routers, schema registries, barrels), the merge train degrades into an $O(N^2)$ rebase-and-retest storm.
- **Adopted mechanism:** Extended [`runtime/scripts/diff_scope.py`](../../runtime/scripts/diff_scope.py) with `--overlap <units.json>` (`detect_scope_overlaps()`) and wired it into [`playbooks/decompose-dag.md`](../../playbooks/decompose-dag.md) and [`runtime/merge-serialization.md`](../../runtime/merge-serialization.md). Before dispatching a wave, the coordinator intersects declared unit `scope` globs against the repository file tree (and literal path prefixes) and emits deterministic `OVERLAP_CHAIN` / `--deps` serialization edges so overlapping slices serialize in the DAG instead of colliding at the merge train.

### Lesson 2: Structured Failure Handover Packets (`runtime/scripts/watchdog.py --handover`)
- **Problem in the field:** Respawning a failed or wedged worker via `worker-start --retry-of` with an unstructured transcript dump pollutes the replacement worker's context window, while respawning with zero context causes the replacement to repeat the exact same dead end.
- **Adopted mechanism:** Extended [`runtime/scripts/watchdog.py`](../../runtime/scripts/watchdog.py) with `--handover <attempt.json>` (`build_failure_handover()`) and wired it into [`runtime/worker-supervision.md`](../../runtime/worker-supervision.md). It enforces the reflection-before-retry gate (`repeating_same_approach` or matching `(failing_command, error_token)` signatures trigger `HANDOVER_ACTION=KILL_OR_PARK`), sanitizes untrusted `stderr` through `guard_text.py`, and formats a bounded ($\le 40$-line) `FAILURE_HANDOVER_V1` block for the replacement worker's TASK.

### Lesson 3: Pre-Dispatch Episodic Memory Hints (`runtime/scripts/search_sessions.py --episodic-hint`)
- **Problem in the field:** Workers starting cold on a recurring surface repeat repository-specific traps already discovered and documented in prior run reports (`PARKED` reasons, `REFLECTION:` notes, or `SUSPECT` audit items), whereas loading full historical run reports blows the token budget.
- **Adopted mechanism:** Extended [`runtime/scripts/search_sessions.py`](../../runtime/scripts/search_sessions.py) with `--episodic-hint` (`build_episodic_hint()`), scanning `docs/runs/*.md` for past `PARKED`, `SUSPECT`, and `REFLECTION:` lines matching the target `--path` globs, sanitizing every line through `guard_text.py` and `_visible`, and capping the output at $\le 15$ lines.

### Lesson 4: Execution-Backed Review Probes in Disposable Sandboxes (`playbooks/risk-review.md`)
- **Problem in the field:** Purely static LLM review lenses suffer from false positives on subtle runtime/state hypotheses unless they can test a reproduction probe without dirtying the reviewed checkout.
- **Adopted mechanism:** Updated [`playbooks/risk-review.md`](../../playbooks/risk-review.md) so specialist lenses can execute ephemeral reproduction probes inside a disposable `orca sandbox` (`--ephemeral-probe`) while keeping the reviewed worktree untouched, and any runtime-behavior `BLOCKER` without an executed probe receipt is explicitly labeled `STATIC_ONLY`.

### Lesson 5: A2A Outcome Card Exporter (`scripts/a2a_export.py`)
- **Problem in the field:** External multi-agent routers speaking the Linux Foundation **A2A (Agent2Agent)** protocol discover sub-fleets through structured JSON Agent Cards declaring capabilities, autonomy, governance gates, and output artifact contracts.
- **Adopted mechanism:** Added [`scripts/a2a_export.py`](../../scripts/a2a_export.py) (tested by [`tests/test_a2a_export.py`](../../tests/test_a2a_export.py)) to project `skills/*/SKILL.md` frontmatter (`unit`, `state_machine`, `convergence`, `ordering`, `parking`, `oracle`, `proof`, `autonomy`) into standard `a2a-agent-card/v1` descriptors bound to [`runtime/evidence-manifest.md`](../../runtime/evidence-manifest.md) and [`runtime/one-way-doors.json`](../../runtime/one-way-doors.json).
