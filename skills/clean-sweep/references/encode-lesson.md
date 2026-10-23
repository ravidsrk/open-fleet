# Playbook — encode-lesson  (REFLECT: a repeated correction becomes unwritable)

Recipe: pstack `correct` (Lauren Tan, cursor/plugins, MIT), restated as fleet rules — no worker loads
pstack, so it carries no pin. compound-learn.md
sends you here when the same correction has happened twice. An agent-context line is not the
fix. Nothing fails when the next agent skips it.

## Pick the highest level that works

Stop at the first level that makes the mistake unwritable.

1. **Architecture.** One owner for the state, one supported way. Delete the old path an agent
   would copy. Hide internals so the wrong import fails. Replace a hand-synced list with one
   source of truth.
2. **Types.** The bad state does not compile.
3. **A lint or CI check** whose error names the file, type, or function to use. When the pattern
   is already common, fail only on a change that adds more.
4. **A test** that calls the behavior the way a user does. A test that would still pass if every
   function it calls returned nothing does not count.
5. **Docs or an agent rule do not finish the lesson.** Use them only to name a judgment call
   that levels 1–4 cannot make unwritable, then park that unit for a human.

## Prove it on a specimen

Name the level, why each higher level does not work, and the specimen: a past commit, diff, or
fixture the new check must fail on. For levels 1–4 the check goes RED on that specimen and
GREEN once the specimen is gone — the same shape as floor-it's PROVE-FIRES. Exceptions sit on
the offending line with a reason, an expiry, and a human's approval. Level 5 has no such check,
so it parks and does not close.

The follow-up is one unit on the park register. It is one-way when it deletes a public API or
freezes a new bar, and mechanical otherwise. A terminal verdict that cites an unenforced instruction
as the fix for a repeated class is not a reflection.

## What this is not

Not a new mission. The denominator is still the mission that noticed the repeat (or floor-it's
dimension, when the fix is a standing gate). Not a license to edit `AGENTS.md`. That file stays
behind compound-learn.md's human approve.

## Completion

The repeat is encoded at the highest level that works, its check RED on the named specimen and
GREEN once the specimen is gone (levels 1–4), or parked as one unit on the park register (level 5).
