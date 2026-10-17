"""The README's three developer-facing images and the six deeper visuals."""
from specs import STYLE, D

def n(id_, prompt, out=None):
    return {"id": id_, "out": out or f"assets/diagrams/{id_}.jpg", **D, "prompt": STYLE + prompt}

NEW = [
n("you-say", """Content: a plain three-column table drawn as three tall panels side by side, headed in uppercase: YOU SAY · THE FLEET RUNS · YOU GET, with four rows aligned across all three panels and one small arrow between the panels on every row.
Row 1:  > ship this   |   freeze → build → review   |   PROMOTION_READY + evidence
Row 2:  > close every issue   |   triage → fix → re-enumerate   |   backlog at zero, SHA-linked
Row 3:  > harden this   |   audit → exploit → re-attack   |   CLEAN re-audit, or named gaps
Row 4:  > why is this flaky   |   reproduce → falsify → prove   |   demonstrated root cause
Every cell is the same plain box: white monospace text, a thin blue outline, no fill colour. The only colour difference: the four YOU GET boxes have a green outline instead of blue. There are NO icons, emoji, check marks, crosses, locks, badges, labels or coloured glows anywhere in the image.
Title, centred at the top: Give a mission a goal. Come back to an evidence-verified end state.
Footer, small, centred: every claim is re-derived from git by a session that did not do the work"""),

n("negative-control", """Content: a head-to-head of two gates on the same input.
Top centre, one small box: the same gamed manifest — the worker quietly reported only AC-1, with a caption beneath: the frozen spec says AC-1 + AC-2
Two large panels side by side beneath it, each fed by an arrow from that box.
Left panel, header: A SELF-SCORING GATE, body: grades the worker's own criteria list — no frozen denominator, no second session, then a large green badge: GREEN — exit 0, caption: it never sees the dropped AC-2
Right panel, header: ORCA-FLEET'S VERIFIER, body: re-derives the criterion set from the frozen spec, in a fresh session, then a large red badge: RED — exit 2, caption: scope: AC-2 not addressed
A strip beneath both panels, small: and for every fix, the negative control — revert it in a fresh worktree and the proof must go RED; a proof that stays GREEN proves nothing
Footer, small, centred: reproduce it: sh demo/negative-control/run.sh"""),

n("install-stack", """Content: left two-thirds: a vertical stack of five wide rounded layer boxes, bottom to top, each with a large label and a caption:
Layer 1, the bottom: Orca app, caption: orchestration experimental feature enabled
Layer 2: orca CLI, caption: orca-ide on Linux outside Orca terminals
Layer 3: orchestration skill + orca-cli skill, caption: the substrate — worktrees, terminals, task DAG, worker_done
Layer 4, drawn with a brighter glow: orca-fleet missions, caption: this repo — the outcome layer
Layer 5, the top: upstream packs, caption: mattpocock/skills · garrytan/gstack · addyosmani/agent-skills — one pack per worker, never two
Right third, header: THREE INSTALL PATHS, three cards stacked vertically:
Card 1: symlink into ~/.claude/skills, caption: references preserved · the completion gate is OFF until you paste the settings snippet, with an amber badge: wire the gate
Card 2: Claude Code plugin, caption: the whole repo copied · completion gate ON by construction, with a green badge: gate on
Card 3: skills CLI, caption: copies sever ../../playbooks — not supported today (#294), with a red badge: broken
Footer, small, centred: scripts/bundle.py --check builds self-contained missions for copy installers"""),

n("gates-terminal", """Content: what a fleet's questions look like from your side of the terminal.
Left, large: a terminal window showing exactly these five monospace lines:
DECISION (freeze grill) · spec/magic-link · token storage
  (a) signed JWT in the link — stateless, no schema change  [recommended]
  (b) DB-backed one-time token — revocable, adds a table
Reply 'a' or 'b'.
No timeout default — the freeze is a one-way gate.
Beneath the window, an amber person icon and the caption: ONE-WAY — waits for you, never defaulted on timeout
Right, two smaller cards stacked vertically:
Card 1, header: TASTE, body: recommendation taken, decision batched into a brief — the run keeps working; you veto later
Card 2, header: PROMOTION, body: the fleet opens the BASE → default PR with a traceability table, and stops — you merge it
Footer, small, centred: mechanical decisions never reach you — auto-resolved, with an audit line"""),

n("artifacts-map", """Content: what a run leaves behind — a file tree on the left, the GitHub side on the right.
Left, a tree of boxes connected by thin lines:
ledger.md, caption: one row per unit — id · exit flags · lighting · PR · reviewed SHA · merge SHA · evidence pointer
docs/runs/<date>-<mission>/ with three child boxes: report.md (caption: RUN: header · terminal state · parked items) · manifest.json per unit (caption: base_sha → head_sha · criteria · commands · negative_control) · inventory (caption: sha256 of every artifact — tamper-evident)
Right, three boxes joined by arrows: one PR per unit → merged into BASE (caption: ancestry-verified · reviewed_sha == head) → the promotion PR, BASE → default (caption: traceability table · left to you)
A small note at the bottom right: worker terminals and traces are for forensics — never the completion oracle
Footer, small, centred: git is truth; the ledger is its cache"""),

n("mission-handoffs", """Content: how missions hand work to each other, laid out as three columns.
Each column has a large target box as its header at the top, and beneath it a stack of smaller source boxes; each source box has one short upward arrow into the header directly above it and a small muted label beside the arrow. Nothing crosses between columns.
Column 1 header: ship-it. Sources beneath it: map-it (label: a frozen map + DAG) · root-cause (label: a fix handoff brief) · attest-it (label: remediation that lands code)
Column 2 header: clean-sweep. Sources beneath it: root-cause (label: a fix handoff brief) · deflake-it (label: deterministic failures are bugs) · prove-it (label: surfaced bugs)
Column 3 header: migrate-it. Sources beneath it: modernize-it (label: an upgrade that forces a schema change) · ship-it (label: a stateful change across deploys)
Below the columns, one extra pair on its own line: oncall-it → root-cause, label: the telemetry a diagnosis consumes
At the bottom, a dashed bracket around three boxes in a row: harden-it → prove-it → ship-it, with a caption: a chain — sequential, each link gated by the previous verified terminal
Every box is the same plain blue-outlined style; no icons anywhere. All mission names are lowercase, exactly as written here (ship-it, not SHIP-IT).
Footer, small, centred: every handoff is a separately authorized run with its own BASE"""),

n("proof-ladder", """Content: a ladder of three rungs drawn as wide boxes, bottom to top, joined by upward arrows whose labels say what advancing requires.
Bottom rung: doctrine-only, caption: the protocol is written; no recorded run
Arrow 1 label: a run report that BINDS — a RUN: header, a manifest in the run's own docs/runs/ directory, an inventory that re-hashes at the commit it names
Middle rung: self-run, caption: run against this repository
Arrow 2 label: the same binding, on a repository other than this catalog
Top rung: external-run, caption: run against any other repository (the tier names the target, not the runner)
Right side, a note with an amber marker: the live state is the archive — docs/runs/README.md names each mission's tier as its evidence lands; the ladder climbs only through the binding gate
Footer, small, centred: a mission is never presented as more proven than its evidence — validate.py enforces the field
Render ONLY the text listed above — no extra captions, no repeated or paraphrased lines, no link hints under the note"""),

n("verify-gate", """Content: the completion gate and its trust boundary.
Top row, left to right, joined by arrows: a box: the coordinator sets the gate env (caption: ORCA_MANIFEST · contract source + digest · unit class) → a box: Stop / TaskCompleted hook fires verify-gate.sh → a box: verify.py re-derives (caption: scope from the frozen contract · review from GitHub · negative control read, or replayed in a throwaway worktree when ORCA_EXECUTE_NC is set) → two outcome boxes stacked: a green one: exit 0 — allow, and a red one: exit 2 — BLOCK, with feedback
Caption under the row: fail-closed — a missing manifest, a missing contract, or a verifier error blocks
Bottom half, header: WHERE THE VERDICT IS SOUND, two cards side by side:
Card 1, amber outline, header: native hook, inside the worker's own session, body: the worker can set ORCA_* itself — ADVISORY, defence in depth
Card 2, green outline, header: CI · MCP-Task · SDK subprocess, body: the coordinator owns the env — SOUND
Footer, small, centred: keep the differentiation in verify.py, not in the hook"""),

n("mission-identity", """Content: the six-point mission-identity test — a checklist card on the left, two worked examples on the right.
Left card, header: THE SAME MISSION ONLY IF ALL SIX MATCH, six numbered lines: 1  unit of work · 2  per-unit state machine · 3  convergence proof · 4  ordering and isolation · 5  parking and failure semantics · 6  the oracle the proof binds to
Right, two example boxes stacked:
Box 1, with a green check mark at its left: first line in white: audit findings · tracker issues · doc claims = one mission: clean-sweep; second, smaller muted line: same proof shape, same repo-suite oracle
Box 2, with a red cross at its left: first line in white: a perf breach ≠ a finding → speed-it; second, smaller muted line: a statistical budget over journeys — a different proof, so a different mission
Footer, small, centred: a different oracle makes a different mission only when it changes the proof's shape or the parking classes"""),

n("threat-boundaries", """Content: the four security boundaries on the left two-thirds as a 2x2 grid of spacious cards, and the five-rung response ladder on the right third as a vertical stack of compact single-line boxes.
Card 1 (top-left): 1 · SANDBOX, caption: isolated worktree · ro / rw / danger · PreToolUse deny-hook · OS ceilings
Card 2 (top-right): 2 · NETWORK, caption: hash-chained egress.py receipts · unreceipted gh writes blocked
Card 3 (bottom-left): 3 · SUPPLY CHAIN, caption: pins.json + pin_review.py audit · one pack per worker · guard_text.py
Card 4 (bottom-right): 4 · IDENTITY & ACCESS, caption: signed dispatch digest · human gates · independent SHA-bound verifier
Right third, five compact single-line boxes top to bottom joined by short downward arrows:
1 STEER — deny-hook nudge (blue outline) → 2 REDUCE — park + ro (blue outline) → 3 STOP — kill worker (amber outline) → 4 REVOKE — rotate creds (red outline) → 5 QUARANTINE — fail-closed (red outline)
Footer, small, centred: security relies on what the layers below the model make impossible or evident"""),

n("tracker-enumeration", """Content: a spacious left-to-right pipeline showing how hosted trackers feed a fleet run safely.
Left column, three compact stacked source boxes merging into one right-pointing arrow:
Box 1 (blue outline): GITHUB, caption: gh issue · pr list
Box 2 (blue outline): LINEAR, caption: orca linear list
Box 3 (green outline): JIRA, caption: orca jira list · search
Followed left-to-right by three spacious rounded stage cards joined by arrows:
Stage 1 (blue outline): T0 TWIN-QUERY, caption: page until truncated is false · reconcile two independent workers
Stage 2 (amber outline): TRUST FENCE, caption: guard_text.py normalizes text · ticket text is data, never authority
Stage 3 (green outline): VERIFIED CLOSURE, caption: single-attempt writeId + reference · proved by merged SHA in manifest
Footer, small, centred: a ticket reflects closure — it never proves it or authorizes writes"""),
]


