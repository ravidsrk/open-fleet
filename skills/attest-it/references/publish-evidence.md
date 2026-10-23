# Playbook — publish-evidence  (take a report or a skill bundle out of the repo)

Recipe: Orca's publishing verbs (`artifacts share/update/unshare/list/delete`,
`skills installed/share`). Any mission phase whose evidence must leave the tree — a rendered
report link, a skill bundle for another host — runs through here. Publishing is an outward
action: the manifest records WHAT went out behind WHICH link, and a link is a credential, not
a citation.

## Artifacts: share, update, unshare, delete

`share`, `update`, and `unshare` accept `.html`, `.htm`, `.md`, and `.markdown` files. Share a
self-contained HTML file or use absolute asset URLs — relative assets are NOT uploaded. `share`
saves the edit token in the active Orca profile and never prints it; `update` and `unshare`
look it up by resolved local path, so reuse the same path AND the same profile. `list` pages
with `nextCursor` until exhausted; `delete` takes the account-owned id from `list` and needs
neither the file nor the token. Past the CLI transport limit, the error names the browser
upload page — follow it. `ORCA_CLOUD_AUTH_TOKEN` is a development-only override: prefer the
profile session and never expose the token in logs or agent output.

## Skill bundles: name every skill, hold the permission

`skills installed` returns safe discovery IDs without local paths; sharing then verifies each
`SKILL.md` declares a portable lowercase hyphenated name. Each `--skill` is an exact discovery
ID or an unambiguous installed name — IDs when names collide. Multiple `--skill` flags make
ONE bundle and ONE link; `--all` and arbitrary paths are intentionally unsupported, so name
every skill the user asked to publish and never widen the set: the permission is authority,
not intent. The agent switch (Settings → Share Skills) is default-off with no CLI way to
grant it — `agent_skill_sharing_disabled` means STOP and ask the human (read human-handoff.md),
never retry. One staged agent bundle per host: on busy, wait, then retry. Run on the Orca
terminal of the machine that stores the skills — forwarded WSL, SSH, and paired-runtime calls
fail before discovery so the wrong filesystem is never read.

## Record the outward step

The JSON result carries the unlisted URL plus the public share/package/version IDs — and never
a cloud token. The manifest binds all of them (evidence-manifest.md): the exact file or skill
set published, the link, the version ids, and the grant that authorized it. Anyone with an
active link can inspect and install without signing in, so the link travels only where the
grant allows; revoking blocks future access but never recalls installed copies.

## Completion

Every published file was self-contained (or absolute-URLed) and every published skill was
explicitly named; the same path and profile served share and update; no denied publish was
retried; no token appears in any log; the manifest carries the URL + version ids + the grant
for each outward step; an unpublished-because-unpermitted item is PARKED to the human, never
published by another route.
