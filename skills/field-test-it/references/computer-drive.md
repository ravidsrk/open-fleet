# Playbook — computer-drive  (drive a desktop app window as an evidence source)

Recipe: Orca's `computer-use` skill (`orca computer` verbs). Any mission phase whose oracle is a
native app window or an external browser window runs through here — the DESKTOP tier. The
embedded browser is `browser-drive`, never this playbook; a shell, file, git, HTTP, or CLI path
that can complete the step always wins over GUI control.

## Preconditions

Resolve the executable for this session first (the stub's `ORCA` placeholder is not a command),
then read capabilities and permissions (`computer capabilities`, `computer permissions`). Prefer
`--json` on every call. Screenshots arrive at `result.screenshot.path`, else inline base64
`result.screenshot.data`; pretty output saves no images.

## The loop is state → act → state

List apps, read state, act, re-read before the next index — element indexes are short-lived and
go stale on any delay, navigation, focus change, scroll, window change, or re-render. Read the
tree and indexes from `result.snapshot.treeText`; `elementCount` is a count, never an index
source. Prefer bundle-id selectors from `list-apps`; for multi-window apps run `list-windows`
first and keep one window selector until the target changes.

## Verified or it did not happen

An action's verification is separate from its provider call: `verified` means the changed value
was read back; `unverified (accessibility action unasserted)`, `unverified (synthetic input)`,
or missing verification metadata — including every response from an older runtime — is
UNVERIFIED. Never report an unverified action as success: if it could have sent, submitted,
bought, or deleted something, the effect is unproven. Prefer semantic actions (`set-value` for
editable fields, `click` for controls, listed secondary-action names only); `type-text` only
into a verified focused receiver; coordinates are window-local — divide screenshot pixels by
`screenshot.scale`, and prefer tree frames over raw pixels.

## Consent: LOOK is granted, ACT is gated

Never push, submit a form, send a message, buy, delete, change account settings, or expose a
secret unless the user explicitly asked for that action; in sensitive content read only what was
requested. A secret payload travels via `--text-stdin` / `--value-stdin`, never the command
line — and on Linux/Windows the payload still crosses a short-lived local operation file, so
unsolicited secrets stay out entirely (sandbox-policy.md).

## Errors fail closed, then re-read

`element_not_found` means the index went stale: re-read state, never retry the index.
`window_not_focused` gets ONE `--restore-window` retry; if restore was already requested, stop
and surface it. `app_blocked` is a stop, not a workaround. Missing-tree or no-screenshot means
hidden, minimized, off-screen, or permission-blocked — run the named `permissions` check, use
the setup UI, then retry. `invalid_argument` is fixed in the flags, never retried unchanged.

## Labelled evidence lines

Every step emits the same labels so a desktop observation diffs mechanically against a rerun:

```
APP=<bundle-id or name>  WINDOW=<id or index>  ACTION=<verb + target>
VERIFIED=<verified | unverified: reason>  ARTIFACT=<path>  (screenshot / tree)
STEP_OK <step-name>
```

An artifact with no `head_sha` in its name cannot bind to a manifest (evidence-manifest.md) and
does not count. A re-verify after a fix is captured by a FRESH worker at the new `head_sha`.

## Completion

Every step re-read state before acting and printed its sentinel; every action carries a
VERIFIED/UNVERIFIED verdict and no UNVERIFIED action is reported as success; every mutating
action has a recorded grant that named it in advance; no credential was typed, read, or passed
outside stdin; every artifact filename carries the `head_sha` it was captured at; a blocked step
is PARKED with the reason, never marked green.
