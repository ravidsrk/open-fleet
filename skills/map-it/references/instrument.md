# Playbook — instrument  (make one production path answerable from telemetry alone)

Recipe: Addy `observability-and-instrumentation` (question-first instrumentation, structured
events, RED/USE, symptom alerts, runbooks) + its pre-launch gate. The unit is ONE production path —
an endpoint, a job, or an external dependency — with its 2–4 on-call questions. `release.md`
already carries the operability gate for a shipped wave (≥1 symptom alert with a runbook,
test-fired); this playbook is the protocol that gate calls for, and `oncall-it` runs it over a
frozen path set.

## 1. The questions ARE the denominator (written before any code)

Telemetry with no question is noise. For the path, write 2–4 questions an on-call engineer will
ask at 2 a.m. into the ledger, before instrumenting — e.g. for `POST /checkout`: what fraction of
payments succeed first attempt vs after retry; when one fails permanently, why (provider error /
timeout / validation); is the provider slower than usual. Every signal added must answer one of
them by name; a signal that answers none is deleted, not kept "just in case". If the questions
cannot be written, the path is not ready to instrument — a park (read human-handoff.md), not a smaller job.

## 2. One signal per question, typed

| Signal | Answers | Cost |
|---|---|---|
| structured log | "what happened in this specific case?" | per event, grows with traffic |
| metric | "how often / how fast, in aggregate?" | fixed per series |
| trace span | "where did the time go across services?" | per request, sampled |

Metrics say **that** something is wrong, traces say **where**, logs say **why**. Record the mapping
`Q<n> → signal` in the ledger; the convergence proof is checked against it.

## 3. Structured events

Log objects, never interpolated prose: a stable `event` name plus machine-readable fields. Levels
used consistently — `error` (invariant broken, someone acts), `warn` (degraded but handled), `info`
(significant business event), `debug` (off in production).

A **correlation ID** is generated or accepted at the system boundary, attached to every line, span,
and outbound call, and returned to the caller. An **entry-point field** is stamped where the run
starts (`scheduler` / `replay_endpoint` / `cli`) and propagated across the same boundaries as the
correlation ID — queue metadata, HTTP headers. A sink written by more than one entry point without
it forces attribution by elimination against records that may no longer exist; a field that merely
correlates with an entry point is a hint, not an attribution.

## 4. Metrics with bounded labels

RED on every endpoint and every external dependency: Rate, Errors, Duration as a **histogram**
(percentiles queryable — an average hides the 1% having a terrible time). USE on resources
(queues, pools, hosts): Utilization, Saturation, Errors. Labels come from small fixed sets — route
template, status class (`2xx`, not `200`), provider name. User ids, raw URLs, request ids, and
error-message text are NEVER labels: that is a cardinality bomb, and it belongs in logs or traces.

## 5. Alert on symptoms, in two severities

Page-worthy symptoms (error rate over budget, p99 past the objective, queue age) — not causes
(CPU, a pod restart, disk). Cause alerts fire when nothing is wrong and miss what you did not
predict. Every alert: actionable (if the answer is "it self-heals", delete it), runbook-linked, and
carrying a threshold + duration justified by an SLO or by pasted historical data, never a guess.
Exactly two severities — **page** (user-facing, act now) and **ticket** (degradation, act this
week); a third trains people to ignore all three. A cardinality-or-cost decision on a paid backend
is a human gate (gate-classification.md), not an agent's call.

## 6. Runbook, three lines minimum

At the repo's own convention (its runbook directory and naming — match it, never invent one),
named after the alert: **Means** (likely cause, one line) · **First check** (the exact query or
command) · **Escalate to** (channel or rotation). Expand past three lines only where the first
check cannot decide. A runbook is corrected as part of closing any incident it was used in.

## 7. Test-fire, then induce

- **Test-fire:** each new alert fired once (threshold temporarily lowered), the receipt from the
  destination channel captured — an alert nobody has seen fire is not an alert.
- **Induce:** break the path in staging. A FRESH worker with **no source access** — telemetry only
  — must name the failing component. Its manifest is the evidence, never the instrumenter's word.
- **Negative control:** on a throwaway branch, remove the instrumentation and re-run the induced
  failure; the source-blind worker must fail to locate it (RED). Green both ways proves nothing.

## 8. Never in telemetry

Secrets, tokens, passwords, whole request bodies, unredacted PII. Allowlist fields; spot-check the
ACTUAL sampled output, not the intent of the code. A leak found here is a finding, not a tidy-up.
## Completion

The questions are frozen; every question maps to a named signal that exists; logs are structured
with stable event names, a correlation ID on every line, and an entry-point field on any
multi-entry sink; RED/USE series exist with bounded labels and queryable percentiles; every alert
is symptom-based with a justified threshold, a linked runbook at the repo's convention, and a
test-fire receipt; an induced staging failure was named by a source-blind worker; the
instrumentation-removed negative control went RED; sampled output carries no PII. A missing
staging or alert channel is `CODE_CLOSED` + `VERIFY_AT_SCALE` with its named verify command —
never a green.
