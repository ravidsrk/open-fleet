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

Portable backends (#585). A transcript naming a `backend` other than orca must also prove the
isolation a disposable sandbox owes: ephemeral, no credential or home mounts, placement bound
before launch, and the backend's own flags (docker family: cap-drop ALL, no-new-privileges, a
pids limit; bwrap: workspace filesystem scope, no host network; gondolin: only /workspace
mounted). Any backend fails on `privileged: true`, host networking, a mount of a container
runtime socket or of a directory holding one (`/run`, `/var/run`, `/run/containerd`, …), or a
mount of the real home directory, /root, a conventional home root (`HOME_ROOTS`: /home, /Users,
/var/home, or a user's home directly under one) whatever the judging machine's `$HOME` is, an
ancestor of any of these, or a credential directory (or an ancestor of one) under them. Other
subdirectories of a home are fine. Mount strings
in `--mount type=bind,source=…` / `src=` form are parsed for their host side too.

Exit codes
    0  the transcript is clear for this recipe
    1  it is not clear: a fail/warn, or a transcript for another recipe (reason on stderr)
    2  a credential or isolation finding — the sandbox would expose the host — or usage
"""
from __future__ import annotations

import json
import os
import re
import sys

# Status/level values that are a doctor telling you something is wrong.
BAD_STATUS = {"fail", "failed", "failing", "failure", "error", "errored", "warn", "warning"}
# Keys whose CONTENTS are the findings, so an empty one is good news.
FINDING_KEYS = ("failures", "warnings", "errors", "problems", "issues")
# Keys whose VALUE is a verdict word.
STATUS_KEYS = ("status", "level", "severity", "state", "result")
# Portable sandbox backends (#585).
DOCKER_FAMILY = {"docker", "devcontainer", "hermes-docker"}
PORTABLE_BACKENDS = DOCKER_FAMILY | {"bwrap", "gondolin", "superset-cloud", "openhands-docker",
                                     "apptainer"}
FORBIDDEN_MOUNT_TOKENS = (".ssh", ".config/gh", ".git/config", "$home", "${home}", ".aws",
                          ".gnupg", ".netrc", ".docker/config.json", ".kube")
# Runtime control sockets: a container holding one can start a privileged sibling.
FORBIDDEN_SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock", "buildkitd.sock")
# Where those sockets live. Mounting the socket OR any directory above it hands it over, so a
# source is refused when it resolves to one of these or to an ancestor of one (#592).
SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                "/var/run/containerd/containerd.sock", "/run/podman/podman.sock",
                "/var/run/podman/podman.sock", "/run/crio/crio.sock", "/run/buildkit/buildkitd.sock",
                "/run/docker/containerd/containerd.sock")
# Per-user runtime dirs (rootless docker/podman keep their sockets there), any uid.
_USER_RUNTIME_DIR = re.compile(r"^/(?:var/)?run/user(?:/[^/]+(?:/(?:podman|docker|containerd))?)?/?$")
# Credential locations under a home directory (the real $HOME and /root alike). The location
# itself and every directory above it expose it; anything else under home is fine.
HOME_CREDENTIALS = (".ssh", ".config/gh", ".aws", ".gnupg", ".netrc", ".docker", ".kube",
                    ".git-credentials", ".gitconfig", ".config/gcloud", ".azure")
# Roots that hold EVERY user's home on the platforms a recipe may target. Judged whatever the
# judging host is: a macOS coordinator (HOME=/Users/x, where /home resolves into
# /System/Volumes/Data) must still refuse a Linux recipe mounting /home (2026-10-23 review, P2-15).
HOME_ROOTS = ("/home", "/Users", "/var/home")

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


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(os.path.expandvars(path)))


_SOURCE_KEYS = ("source", "src", "host", "hostpath", "host_path")
_TARGET_KEYS = ("target", "dst", "destination", "containerpath", "container_path")


def _dict_get(mount_item: dict, keys) -> str:
    """Case-insensitive: `docker inspect` spells them Source/Destination."""
    low = {str(k).lower(): v for k, v in mount_item.items()}
    for key in keys:
        if low.get(key):
            return str(low[key])
    return ""


def _mount_fields(spec: str) -> dict | None:
    """`[--mount[=| ]]type=bind,source=/x,target=/y[,readonly]` as a dict, else None.

    A long-form mount string is comma-separated key=value pairs; reading it as `src:dst` took
    `type=bind,source=/home,…` for a (relative, harmless) source and passed the real home (#592).
    """
    s = spec.strip()
    for flag in ("--mount=", "--mount ", "--volume=", "--volume ", "-v "):
        if s.startswith(flag):
            s = s[len(flag):].strip()
            break
    if "=" not in s.split(",", 1)[0]:
        return None
    out = {}
    for part in s.split(","):
        key, eq, value = part.partition("=")
        out[key.strip().lower()] = value.strip() if eq else "true"
    return out


def _mount_source(mount_item) -> str:
    """The HOST side of a mount: `source`/`src`/`host`, or the first field of `src:dst[:mode]`."""
    if isinstance(mount_item, dict):
        return _dict_get(mount_item, _SOURCE_KEYS)
    fields = _mount_fields(str(mount_item))
    if fields is not None:
        return _dict_get(fields, _SOURCE_KEYS)
    s = str(mount_item).strip()
    for flag in ("--volume=", "--volume ", "-v "):
        if s.startswith(flag):
            s = s[len(flag):].strip()
            break
    return s.split(":", 1)[0]


def _mount_target(mount_item) -> str:
    if isinstance(mount_item, dict):
        return _dict_get(mount_item, _TARGET_KEYS)
    fields = _mount_fields(str(mount_item))
    if fields is not None:
        return _dict_get(fields, _TARGET_KEYS)
    parts = str(mount_item).split(":")
    return parts[1] if len(parts) > 1 else parts[0]


def _covers(real: str, path: str) -> bool:
    """`real` IS `path` or a directory above it."""
    return real == path or path.startswith(real.rstrip("/") + "/")


def _socket_paths() -> list[str]:
    paths = list(SOCKET_PATHS)
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    for base in ([xdg] if xdg else []) + [f"/run/user/{os.getuid()}"]:
        paths += [os.path.join(base, "docker.sock"), os.path.join(base, "podman", "podman.sock")]
    docker_host = os.environ.get("DOCKER_HOST") or ""
    if docker_host.startswith("unix://"):
        paths.append(docker_host[len("unix://"):])
    # Both spellings: /var/run is a symlink to /run on most hosts, and a source is compared
    # resolved, so the socket must be too.
    return list(dict.fromkeys(paths + [os.path.realpath(x) for x in paths]))


def _mount_exposes_host(mount_item) -> str | None:
    """A reason when the host side is the real home, /root, a home root (`HOME_ROOTS`) or any
    user's home directly under one, an ancestor of any of these, a credential directory under a
    home (or a directory above one), or a runtime socket / a directory holding one.

    A SUBDIRECTORY of home or /root is fine — worktrees live under ~/.open-fleet/state/…, and a
    root user's repos live under /root — so this compares resolved paths rather than prefixes of
    the spelling.
    """
    source = _mount_source(mount_item).strip()
    if not source:
        return None
    low = source.lower()
    for sock in FORBIDDEN_SOCKETS:
        if sock in low:
            return f"mount exposes the container runtime socket: {source!r}"
    real = _real(source)
    for sock in _socket_paths():
        if _covers(real, sock):
            return f"mount exposes the container runtime socket {sock!r} through {source!r}"
    if _USER_RUNTIME_DIR.match(real):
        return f"mount exposes a per-user runtime directory (rootless container sockets): {source!r}"
    # The path as spelled (normalized) AND as resolved here: a recipe's host is not always the
    # judge's, so a symlinked or absent root on this host must not hide the spelled one.
    seen = list(dict.fromkeys((real, os.path.normpath(os.path.expanduser(os.path.expandvars(source))))))
    guarded = [(_real("~"), "the real home directory"), ("/root", "/root")]
    for root in HOME_ROOTS:
        for root_form in dict.fromkeys((root, os.path.realpath(root))):
            for path in seen:
                if _covers(path, root_form):
                    return f"mount exposes every user's home ({root}): {source!r}"
                if path.startswith(root_form + "/"):
                    user = path[len(root_form) + 1:].split("/", 1)[0]
                    guarded.append((os.path.join(root_form, user), f"the home directory {root}/{user}"))
    for guarded_home, label in guarded:
        for path in seen:
            if _covers(path, guarded_home):
                return f"mount exposes {label}: {source!r}"
            for cred in HOME_CREDENTIALS:
                if _covers(path, os.path.join(guarded_home, cred)):
                    return f"mount exposes {label}/{cred}: {source!r}"
    return None


def _isolation(doc: dict) -> dict:
    iso = doc.get("isolation")
    return iso if isinstance(iso, dict) else {}


def _field(doc: dict, *names):
    """First present value among `names`, in `isolation` first, then at the top level."""
    for scope in (_isolation(doc), doc):
        for name in names:
            if name in scope:
                return scope[name]
    return None


def _all_mounts(doc: dict) -> list:
    out = []
    for mount_key in ("mounts", "volumes", "bind_mounts", "binds"):
        for scope in (doc, _isolation(doc)):
            mounts = scope.get(mount_key)
            if isinstance(mounts, list):
                out.extend(mounts)
    return out


def _backend_findings(backend: str, doc: dict) -> list[str]:
    """The flags a backend must carry to be a disposable sandbox rather than a host shell."""
    issues = []
    if _field(doc, "privileged") is True:
        issues.append("privileged=true (a privileged container is the host)")
    network = str(_field(doc, "network", "networkMode", "network_mode", "networkScope") or "").lower()
    if network == "host":
        issues.append("network=host shares the host network namespace")
    if backend in DOCKER_FAMILY:
        cap_drop = _field(doc, "capDrop", "cap_drop", "capabilitiesDrop")
        caps = [str(c).upper() for c in cap_drop] if isinstance(cap_drop, list) else (
            [str(cap_drop).upper()] if cap_drop else [])
        if "ALL" not in caps:
            issues.append(f"{backend}: capDrop must include ALL (--cap-drop ALL)")
        if _field(doc, "noNewPrivileges", "no_new_privileges") is not True:
            issues.append(f"{backend}: noNewPrivileges=true required (--security-opt no-new-privileges)")
        pids = _field(doc, "pidsLimit", "pids_limit")
        if isinstance(pids, bool) or not isinstance(pids, int) or pids <= 0:
            issues.append(f"{backend}: a positive pidsLimit is required (--pids-limit)")
    elif backend == "bwrap":
        scope = str(_field(doc, "networkScope", "network_scope") or "").lower()
        if not scope or scope == "host":
            issues.append("bwrap: networkScope must be set and must not be host (--unshare-net)")
        if str(_field(doc, "filesystemScope", "filesystem_scope") or "").lower() != "workspace":
            issues.append("bwrap: filesystemScope=workspace required (read-only root, tmpfs home)")
    elif backend == "gondolin":
        mounts = _all_mounts(doc)
        if not mounts:
            issues.append("gondolin: the unit worktree must be the one mount, at /workspace")
        for m in mounts:
            target = _mount_target(m).rstrip("/") or "/"
            if target != "/workspace" and not target.startswith("/workspace/"):
                issues.append(f"gondolin: mounts only /workspace, found {target!r}")
    return issues


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
    for m in list(cred_mounts if isinstance(cred_mounts, list) else []) + _all_mounts(doc):
        for reason in (_mount_exposes_credentials(m), _mount_exposes_host(m)):
            if reason:
                issues.append(reason)
    if doc.get("prelaunch_placement_bound") is not True:
        issues.append("prelaunch_placement_bound=true required")
    issues.extend(_backend_findings(backend, doc))
    return list(dict.fromkeys(issues))


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


def _portable_doc(doc):
    """The doctor report proper. `orca_cli.py` wraps a non-Orca provider's answer in an
    `{"ok": …, "result": {…}}` envelope; reading only the top level would skip every
    portable isolation check on exactly the runtimes that need them."""
    if isinstance(doc, dict) and "backend" not in doc and isinstance(doc.get("result"), dict):
        return doc["result"]
    return doc


def placement_bound(raw) -> bool:
    """Whether the transcript is a PORTABLE backend that binds the worker's placement before
    launch. Orca's own doctor proves recipe health only, so it never answers yes here."""
    try:
        doc = _portable_doc(json.loads(raw))
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    backend = str(doc.get("backend") or "").strip().lower()
    return backend in PORTABLE_BACKENDS and doc.get("prelaunch_placement_bound") is True \
        and not portable_findings(doc)


def assess(raw, recipe):
    """(clear, reason, exposes_host). `exposes_host` marks a credential/isolation finding — the
    exit-2 class — apart from an ordinary fail/warn."""
    try:
        doc = _portable_doc(json.loads(raw))
    except ValueError:
        doc = None

    if not names_recipe(doc, raw, recipe):
        return False, f"doctor output does not name recipe {recipe!r}", False

    if doc is not None:
        isolation = portable_findings(doc) if isinstance(doc, dict) else []
        if isolation:
            return False, "sandbox isolation: " + "; ".join(isolation[:4]), True
        bad = sorted(set(findings(doc)))
        if bad:
            return False, "doctor reports " + ", ".join(bad[:4]), False
        return True, "", False

    stripped = _EMPTY.sub(" ", raw)
    if _BAD_WORD.search(stripped):
        line = next((ln.strip() for ln in stripped.splitlines() if _BAD_WORD.search(ln)), "")
        return False, f"doctor is not clear: {line[:120]!r}", False
    return True, "", False


def verdict(raw, recipe):
    """(clear, reason). `clear` is True only when the transcript is about THIS recipe, reports
    no fail and no warn, and — for a portable backend — proves its isolation."""
    clear, reason, _exposes = assess(raw, recipe)
    return clear, reason


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    require_placement = bool(argv) and argv[0] == "--require-placement"
    if require_placement:
        argv = argv[1:]
    if len(argv) != 2:
        print("usage: sandbox_doctor.py [--require-placement] <transcript> <recipe-id>",
              file=sys.stderr)
        return 2
    path, recipe = argv
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as err:
        print(f"cannot read the doctor transcript: {err}", file=sys.stderr)
        return 1
    clear, reason, exposes_host = assess(raw, recipe)
    if not clear:
        print(reason, file=sys.stderr)
        return 2 if exposes_host else 1
    if require_placement and not placement_bound(raw):
        print("no portable sandbox backend in this transcript binds the worker's placement "
              "before launch (backend + prelaunch_placement_bound=true)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
