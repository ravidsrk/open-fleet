#!/usr/bin/env python3
"""Read an `orca vm recipe doctor <recipe> --provision` transcript and say whether it is CLEAR.

sandbox-policy.md states the rule the `danger` lane rests on: clear means **no `fail` AND no
`warn`**; `ok:true` on its own proves nothing, because a warn is a lane that boots and then fails
a build halfway through (`orca-per-workspace-env`'s doctor-verdict section (cited by name, not line — line pins rot, #382)).

`spawn_worker.sh` used to enforce that rule with `grep -qiE '(^|[^a-z])(fail|warn)'` over a file
the CALLER named, which got the answer wrong in both directions (#283):

* `/etc/passwd` passed — it names "root" and carries neither word, so `ORCA_SANDBOX_RECIPE=root`
  plus `ORCA_SANDBOX_DOCTOR=/etc/passwd` spawned a danger worker;
* a genuine transcript carrying `"failures": []` was REFUSED, because the substring "fail" is
  right there inside the word that reports there were none.

The caller-named file is gone — `spawn_worker.sh` runs the doctor itself now and passes its own
output here. What is left for this module is reading the verdict without either mistake: read it
STRUCTURALLY where the output is JSON, and where it is plain text ignore the shapes that mean
"none of these" before looking for the words that mean "some of these".

Exit codes
    0  the transcript is clear for this recipe
    1  it is not (the reason goes to stderr)
    2  usage
"""
from __future__ import annotations

import json
import re
import sys

# Status/level values that are a doctor telling you something is wrong.
BAD_STATUS = {"fail", "failed", "failing", "failure", "error", "errored", "warn", "warning"}
# Keys whose CONTENTS are the findings, so an empty one is good news.
FINDING_KEYS = ("failures", "warnings", "errors", "problems", "issues")
# Keys whose VALUE is a verdict word.
STATUS_KEYS = ("status", "level", "severity", "state", "result")
# Portable sandbox backends (#585).
PORTABLE_BACKENDS = {"docker", "bwrap", "gondolin", "superset-cloud", "openhands-docker"}
FORBIDDEN_MOUNT_TOKENS = (".ssh", ".config/gh", ".git/config", "$home", "${home}")

# "none of these", in the text forms a doctor writes them: "failures": [], failures: 0,
# warnings={}, errors: none, 0 warnings, no failures.
_EMPTY = re.compile(
    r"""["']?(?:fail(?:ure)?s?|warn(?:ing)?s?|errors?|problems?|issues?)["']?\s*[:=]\s*"""
    r"""(?:\[\s*\]|\{\s*\}|0\b|none\b|null\b|false\b)"""
    r"""|\b(?:0|no)\s+(?:fail(?:ure)?s?|warn(?:ing)?s?|errors?|problems?|issues?)\b""",
    re.IGNORECASE,
)
_BAD_WORD = re.compile(r"(^|[^a-z])(fail|warn|error)", re.IGNORECASE)


def _mount_exposes_credentials(mount_item) -> str | None:
    """Return a reason if a mount specification exposes ~/.ssh, ~/.config/gh, .git/config, or $HOME."""
    if isinstance(mount_item, dict):
        parts = [str(v) for v in mount_item.values() if v is not None]
    else:
        parts = [str(mount_item)]
    for raw_part in parts:
        for seg in raw_part.split(":"):
            s = seg.strip()
            low = s.lower()
            for tok in FORBIDDEN_MOUNT_TOKENS:
                if tok in low:
                    return f"credential_mount exposes {tok}: {raw_part!r}"
            if s in ("~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/"):
                return f"credential_mount exposes $HOME: {raw_part!r}"
    return None


def portable_findings(doc: dict) -> list[str]:
    """Validate portable sandbox recipe invariants (#585) when `backend` is specified."""
    if not isinstance(doc, dict) or "backend" not in doc:
        return []
    backend = str(doc.get("backend") or "").strip().lower()
    if backend in ("orca", "orca-vm"):
        return []
    if backend not in PORTABLE_BACKENDS:
        return [f"unsupported sandbox backend={backend!r}"]
    issues = []
    if doc.get("ok") is not True:
        issues.append("ok=true required")
    if doc.get("ephemeral") is not True:
        issues.append("ephemeral=true required")
    cred_mounts = doc.get("credential_mounts")
    if not isinstance(cred_mounts, list):
        issues.append("credential_mounts=[] required")
    else:
        for m in cred_mounts:
            reason = _mount_exposes_credentials(m)
            if reason:
                issues.append(reason)
        if len(cred_mounts) > 0:
            issues.append(f"credential_mounts={len(cred_mounts)} (must be empty)")
    for mount_key in ("mounts", "volumes", "bind_mounts"):
        mounts = doc.get(mount_key)
        if isinstance(mounts, list):
            for m in mounts:
                reason = _mount_exposes_credentials(m)
                if reason:
                    issues.append(reason)
    if doc.get("prelaunch_placement_bound") is not True:
        issues.append("prelaunch_placement_bound=true required")
    return issues


def findings(obj):
    """Every fail/warn the doctor structurally reports. An empty collection reports nothing."""
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            low = str(key).lower()
            if low in FINDING_KEYS:
                if isinstance(value, (list, tuple, dict)):
                    if len(value):
                        found.append(f"{key}={len(value)}")
                        found += findings(value)
                elif isinstance(value, bool):
                    if value:
                        found.append(f"{key}=true")
                elif isinstance(value, (int, float)):
                    if value:
                        found.append(f"{key}={value}")
                elif isinstance(value, str) and value.strip().lower() not in ("", "none", "0"):
                    found.append(f"{key}={value.strip()[:40]}")
            elif low in STATUS_KEYS and str(value).strip().lower() in BAD_STATUS:
                found.append(f"{key}={value}")
            elif low == "ok" and value is False:
                found.append("ok=false")
            else:
                found += findings(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found += findings(item)
    return found


def names_recipe(doc, raw, recipe):
    """Whether the transcript names THIS recipe — the whole id, not a piece of a longer one.

    A substring test passed a transcript for `web-prod-privileged` when asked about `web`, and
    about `prod` (#298). Recipe ids are drawn from [A-Za-z0-9._-], so in JSON the
    exact answer is a string VALUE equal to the id, and in plain text it is the id bounded by
    characters an id cannot contain — the reading `grep -F -x` gives a line, applied to a token.
    """
    want = recipe.lower()
    if doc is not None:
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                if node.lower() == want:
                    return True
            elif isinstance(node, dict):
                stack.extend(node.keys())
                stack.extend(node.values())
            elif isinstance(node, (list, tuple)):
                stack.extend(node)
        return False
    return re.search(r"(?<![A-Za-z0-9._-])" + re.escape(recipe) + r"(?![A-Za-z0-9._-])",
                     raw, re.IGNORECASE) is not None


def verdict(raw, recipe):
    """(clear, reason). `clear` is True only when the transcript is about THIS recipe and reports
    no fail and no warn."""
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None

    if not names_recipe(doc, raw, recipe):
        return False, f"doctor output does not name recipe {recipe!r}"

    if doc is not None:
        bad = sorted(set(findings(doc) + (portable_findings(doc) if isinstance(doc, dict) else [])))
        if bad:
            return False, "doctor reports " + ", ".join(bad[:4])
        return True, ""

    stripped = _EMPTY.sub(" ", raw)
    if _BAD_WORD.search(stripped):
        line = next((ln.strip() for ln in stripped.splitlines() if _BAD_WORD.search(ln)), "")
        return False, f"doctor is not clear: {line[:120]!r}"
    return True, ""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("usage: sandbox_doctor.py <transcript> <recipe-id>", file=sys.stderr)
        return 2
    path, recipe = argv
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as err:
        print(f"cannot read the doctor transcript: {err}", file=sys.stderr)
        return 1
    clear, reason = verdict(raw, recipe)
    if not clear:
        print(reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
