# Third-party notices

open-fleet is MIT-licensed ([LICENSE](LICENSE)). It composes recipes from, and runs on, the
projects below. Each playbook names the recipe it adapts in its first lines; this file carries
the upstream notices in one place, as the MIT license asks of substantial portions.

open-fleet is an independent, community-maintained project. It is not affiliated with or
endorsed by Stably (the maker of Orca) or by the authors of the packs below.

| Project | Role here | License | Copyright |
|---|---|---|---|
| [stablyai/orca](https://github.com/stablyai/orca) | the default runtime the missions ride; its served skill guides are archived as re-pin receipts under `docs/runs/` | MIT | stablyai |
| [mattpocock/skills](https://github.com/mattpocock/skills) | recipes adapted in playbooks (grilling, to-spec, to-tickets, tdd, diagnosing-bugs, code-review, research, wizard, resolving-merge-conflicts — removed upstream in v1.3.0, codebase-design, agent-brief) | MIT | Copyright (c) 2026 Matt Pocock |
| [garrytan/gstack](https://github.com/garrytan/gstack) | recipes adapted in playbooks (review-army dispatch, ship's release state machine, canary, plan reviews, document-release, qa browser rules, user-challenge governance) | MIT | Copyright (c) 2026 Garry Tan |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | recipes adapted in playbooks (incremental-implementation, debugging-and-error-recovery, security/perf/a11y/data-migration lenses, deprecation-and-migration, observability-and-instrumentation, documentation-and-adrs) | MIT | Copyright (c) 2025 Addy Osmani |
| [cursor/plugins pstack](https://github.com/cursor/plugins/tree/main/pstack) | recipes adapted in `explain-the-number` and `encode-lesson` (benchmark checklist, prove-the-number, repeated-correction ladder) | MIT | Copyright (c) 2026 Lauren Tan |
| [a2aproject/A2A](https://github.com/a2aproject/A2A) | `specification/a2a.proto` and two example AgentCards from `docs/specification.md`, vendored unmodified at commit `1205f459` as `scripts/vendor/a2a/` and `tests/fixtures/a2a/` (pinned in `scripts/vendor/a2a/PIN.json`) so the A2A export is validated offline | Apache-2.0 (full text in `scripts/vendor/a2a/LICENSE`) | the A2A project authors (the LICENSE names no holder) |
| Ed25519 reference implementation (D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang; ed25519.cr.yp.to) | vendored as `runtime/scripts/ed25519.py`, ported to Python 3 with verification hardening | public domain | — |

Copyright notices for the packs above the pstack row were read from each project's `LICENSE`
file on 2026-09-28. The pstack notice was read from its `LICENSE` on 2026-10-12. The MIT License
text they share:

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The pinned upstream commits the catalog was witnessed against are in
[runtime/pins.json](runtime/pins.json).
