#!/usr/bin/env python3
"""preflight.py — hard preflight checks for a fleet run.

Verifies the invariants that, if wrong, silently corrupt a whole run:
    1. `git` and `gh` are on PATH.
    2. The current directory is a git repo with a working `gh` remote.
    3. The integration BASE branch is NOT the default branch (M-5 guardrail — every
       per-finding PR merges into BASE, so `BASE == default` sends fixes straight to
       production, bypassing the anti-inflation gate and the human promotion review).
    4. BASE exists (locally or on origin).
    5. BASE shares history with the default branch (a merge-base exists); rejects a BASE
       created off an unrelated history. This alone does NOT prove BASE is fresh — a stale
       BASE from an earlier run also has a merge-base. Pass `--fork-point <sha>` (the SHA
       this run branched BASE from) to additionally require merge-base == that SHA.
    6. If `--require-gitleaks` is passed (integrator will scan diffs), `gitleaks` must be
       on PATH; otherwise a soft warning is fine.
    7. If `--mission <name>` is passed, that mission and the playbooks it composes are
       not quarantined (#558). The deny-list resolves from the FLEET catalog —
       $ORCA_FLEET_ROOT, then $CLAUDE_PLUGIN_ROOT, then this script's own catalog —
       never from the target repo in cwd, which must not be able to shadow it. A
       present-but-malformed deny-list refuses the run; none anywhere means no
       quarantine is in force. Runs in readonly mode too: report-only fleets
       dispatch missions all the same.

The BASE/default comparison canonicalizes ref aliases first (D1 remediation):
`origin/main`, `refs/remotes/origin/main`, and `refs/heads/main` all reduce to `main`,
so aliasing the default branch cannot slip past the M-5 guardrail.
An online default derived from gh resolves through refs/remotes/origin/<branch>,
never a possibly stale local namesake. Fetch origin before running preflight;
a missing remote-tracking ref fails closed. Explicit --default refs retain their
local/offline meaning.

Usage:
    preflight.py --base <base-branch> [--default <default-branch>] [--fork-point <sha>] [--require-gitleaks]
    preflight.py --mode readonly        # read-only fleets: binary checks only, no gh/BASE
    preflight.py --offline --base <base-branch> --default <default-branch>   # offline start
    # exit 0 = OK; exit 1 = usage/dependency; exit 2 = invariant violation
    # (usage errors from argparse itself — unknown flag, bad choice — are also exit 1)

Offline start (--offline): gh is skipped entirely. --default becomes required (there is
no gh to derive it) and the gh-remote check is dropped, but every git-based BASE
invariant (3-6) still runs — --offline never weakens the M-5 guardrail. This is the
Phase 0 twin of the mid-run no-gh fallback in merge-serialization.md: the run works
PR-less from unit one, stops at BASE, and owes a human promotion PR. Every subprocess
call carries a timeout, so a gh that hangs (rather than fails) cannot block Phase 0;
the timeout error suggests --offline for intentionally offline hosts.

Wire it in at Phase 0 of the run (SKILL.md) and inside the integrator preamble before the
first `gh pr create` so a mid-run drift is caught, not tolerated.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load_gitexec():
    """gitexec.py, the sibling holding the one git resolution + hardened-env rule."""
    spec = importlib.util.spec_from_file_location(
        "gitexec", Path(__file__).resolve().parent / "gitexec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load_gitexec()


# git commands here are local and fast; gh talks to the network. Read at call
# time (not bound as defaults) so tests can patch them.
_GIT_TIMEOUT = 10
_GH_TIMEOUT = 30


class _UsageExit1Parser(argparse.ArgumentParser):
    """argparse exits 2 on its own usage errors (unknown flag, bad choice), but the
    contract reserves 2 for invariant violations — remap every usage error to 1."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(1)


def _run(cmd: list[str], timeout: float | None = None) -> tuple[int | None, str, str]:
    """rc is None when the command timed out — a sentinel no real process can
    produce (real rcs are 0-255, or negative for a signal death), so a genuine
    `exit 124` is never mistaken for a timeout."""
    limit = _GIT_TIMEOUT if timeout is None else timeout
    env = None
    if cmd[:1] == ["git"]:
        # Every git leg reads the target repo: the absolute git, under the hardened env.
        cmd, env = gitexec.argv(*cmd[1:]), gitexec.env()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=limit, env=env)
    except subprocess.TimeoutExpired:
        return None, "", f"`{' '.join(cmd)}` timed out after {limit}s"
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _default_branch_via_gh() -> str | None:
    rc, out, _ = _run(
        ["gh", "repo", "view", "--json", "defaultBranchRef", "-q", ".defaultBranchRef.name"],
        timeout=_GH_TIMEOUT,
    )
    return f"refs/remotes/origin/{out}" if rc == 0 and out else None


def _branch_exists(name: str) -> bool:
    """True only for an actual local or origin BRANCH — tags and raw SHAs resolve
    via rev-parse but are NOT acceptable as an integration BASE."""
    if name.startswith("refs/"):
        rc, _, _ = _run(["git", "show-ref", "--verify", "--quiet", name])
        return rc == 0 and (name.startswith("refs/heads/") or name.startswith("refs/remotes/"))
    for full in (f"refs/heads/{name}", f"refs/remotes/origin/{name}"):
        rc, _, _ = _run(["git", "show-ref", "--verify", "--quiet", full])
        if rc == 0:
            return True
    return False


def _ref_candidates(ref: str) -> tuple[str, ...]:
    if ref.startswith("refs/"):
        # rev-parse/merge-base can resolve even a qualified-looking name through
        # a local alias. Pin the exact ref before using it in revision lookups.
        rc, out, _ = _run(["git", "show-ref", "--verify", "--hash", ref])
        return (out,) if rc == 0 and out else ()
    return (ref, f"origin/{ref}")


def _merge_base(a: str, b: str) -> str | None:
    a_refs, b_refs = _ref_candidates(a), _ref_candidates(b)
    # Preserve the existing preference order for unqualified local/origin pairs.
    for i, j in ((0, 0), (1, 1), (0, 1), (1, 0)):
        if i >= len(a_refs) or j >= len(b_refs):
            continue
        rc, out, _ = _run(["git", "merge-base", a_refs[i], b_refs[j]])
        if rc == 0 and out:
            return out
    return None


def _canon_branch(ref: str) -> str:
    """Reduce a ref alias to its canonical branch name.

    `origin/main`, `refs/remotes/origin/main`, and `refs/heads/main` all reduce to
    `main`. Prefers git's own resolution; falls back to prefix stripping when the
    ref does not resolve to a symbolic name (e.g. a raw SHA).
    """
    rc, full, _ = _run(["git", "rev-parse", "--symbolic-full-name", ref])
    if rc == 0 and full:
        if full.startswith("refs/remotes/"):
            rest = full[len("refs/remotes/"):]
            return rest.split("/", 1)[1] if "/" in rest else rest
        if full.startswith("refs/heads/"):
            return full[len("refs/heads/"):]
        return full
    name = ref
    for prefix in ("refs/remotes/", "refs/heads/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    if name.startswith("origin/"):
        name = name[len("origin/"):]
    return name


def _tip_sha(ref: str) -> str | None:
    for candidate in _ref_candidates(ref):
        rc, out, _ = _run(["git", "rev-parse", "--verify", "--quiet", candidate])
        if rc == 0 and out:
            return out
    return None


def _catalog_roots() -> list[Path]:
    """Where the fleet catalog may live, most explicit first. The target repo
    in cwd is NEVER a candidate: it must not shadow the fleet's deny-list with
    one of its own (read at call time so tests can patch the environment)."""
    roots = []
    for var in ("OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT", "CLAUDE_PLUGIN_ROOT"):
        value = os.environ.get(var)
        if value:
            roots.append(Path(value))
    roots.append(Path(__file__).resolve().parents[2])
    return roots


def _quarantine_refusal(mission: str) -> str | None:
    """Why this mission may not start under runtime/quarantine.json, or None.

    The matcher lives in quarantine_check.py beside this file (loaded by path,
    so preflight and the catalog validator enforce one rule). No deny-list in
    any catalog root = no quarantine in force; present but malformed or
    unloadable = refusal: the run cannot prove it is allowed.
    """
    root = next(
        (r for r in _catalog_roots()
         if os.path.lexists(r / "runtime" / "quarantine.json")),
        None,
    )
    if root is None:
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_quarantine_check", Path(__file__).resolve().parent / "quarantine_check.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as err:  # a checker that will not load cannot clear a run
        return f"quarantine_check.py unloadable ({err}) — refusing rather than assuming clean"
    entries, errors, _ = module.load_quarantine(root)
    if errors:
        return "runtime/quarantine.json is malformed: " + "; ".join(errors)
    try:
        view = module.mission_view(root, mission)
    except module.QuarantineError as err:
        return str(err)
    found = module.violations(entries, view)
    if found:
        return "; ".join(found)
    return None


def _active_runtime(explicit: str | None) -> str | None:
    """Return explicit `--runtime` or `OPEN_FLEET_RUNTIME` / `ORCA_FLEET_RUNTIME` if set."""
    if explicit and explicit.strip():
        return explicit.strip()
    for var in ("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME"):
        val = (os.environ.get(var) or "").strip()
        if val:
            return val
    return None


def _capabilities_refusal(
    mission: str | None,
    runtime: str,
    *,
    strict_native: bool = False,
) -> tuple[str | None, dict[str, Any]]:
    """Validate runtime provider and mission required capabilities (#586).

    Returns `(refusal_reason_or_None, structured_info)`. Fails closed (non-None
    refusal) if `runtime/providers/capabilities.json` is missing/malformed, if
    `runtime` is unknown, if `mission` is unknown, or if any required capability
    of `mission` is not provided by `runtime`.
    """
    root = next(
        (r for r in _catalog_roots()
         if os.path.lexists(r / "runtime" / "providers" / "capabilities.json")),
        None,
    )
    if root is None:
        msg = "runtime/providers/capabilities.json is missing — refusing rather than assuming capabilities"
        return msg, {"ok": False, "error": msg}
    cap_path = root / "runtime" / "providers" / "capabilities.json"
    try:
        data = json.loads(cap_path.read_text(encoding="utf-8"))
    except Exception as err:
        msg = f"runtime/providers/capabilities.json is malformed ({err})"
        return msg, {"ok": False, "error": msg}
    if not isinstance(data, dict):
        msg = "runtime/providers/capabilities.json must be a JSON object"
        return msg, {"ok": False, "error": msg}
    providers = data.get("providers")
    missions = data.get("missions")
    if not isinstance(providers, dict) or not isinstance(missions, dict):
        msg = "runtime/providers/capabilities.json is missing 'providers' or 'missions' map"
        return msg, {"ok": False, "error": msg}

    provider_name = runtime.strip().lower()
    if provider_name == "auto":
        override = (os.environ.get("OPEN_FLEET_CLI_COMMAND") or os.environ.get("ORCA_CLI_COMMAND") or "").strip()
        platform_bin = "orca" if sys.platform == "darwin" else "orca-ide"
        provider_name = "orca" if (override or _which(platform_bin)) else "posix"
    if provider_name not in providers:
        known = ", ".join(sorted(providers))
        msg = f"unknown_runtime: {runtime!r} is not a registered RPI provider (known: {known})"
        return msg, {"ok": False, "runtime": runtime, "error": msg}

    p_entry = providers[provider_name]
    if not isinstance(p_entry, dict):
        msg = f"runtime/providers/capabilities.json provider {provider_name!r} is malformed"
        return msg, {"ok": False, "runtime": provider_name, "error": msg}

    native = set(p_entry.get("native_capabilities") or [])
    fallback = set(p_entry.get("fallback_capabilities") or [])
    available = native if strict_native else (native | fallback)

    if mission:
        if mission not in missions or not isinstance(missions[mission], dict):
            msg = f"unknown_mission: {mission!r} is not declared in runtime/providers/capabilities.json"
            return msg, {"ok": False, "mission": mission, "runtime": provider_name, "error": msg}
        m_entry = missions[mission]
        required = list(m_entry.get("required") or [])
        missing = [cap for cap in required if cap not in available]
        if missing:
            first = missing[0]
            mode_note = " (strict-native)" if strict_native else ""
            missing_str = ", ".join(f"missing_capability: {c}" for c in missing)
            msg = f"mission {mission!r} cannot run on runtime {provider_name!r}{mode_note} — {missing_str}"
            return msg, {
                "ok": False,
                "mission": mission,
                "runtime": provider_name,
                "strict_native": strict_native,
                "missing_capability": first,
                "missing_capabilities": missing,
                "error": msg,
            }

    return None, {
        "ok": True,
        "mission": mission,
        "runtime": provider_name,
        "strict_native": strict_native,
        "capabilities": sorted(available),
    }


def main(argv: list[str]) -> int:
    parser = _UsageExit1Parser(prog="preflight.py")
    parser.add_argument("--base", help="The integration BASE branch name (required unless --mode readonly).")
    parser.add_argument("--default", help="Default branch (auto-derived via `gh` if omitted).")
    parser.add_argument(
        "--fork-point",
        help="SHA this run branched BASE from; preflight fails unless merge-base(BASE, default) == this "
        "(catches a stale BASE left over from an earlier run).",
    )
    parser.add_argument(
        "--mode",
        choices=("write", "readonly"),
        default="write",
        help="readonly: binary/repo checks only — for report-only fleets that never open PRs.",
    )
    parser.add_argument(
        "--require-gitleaks",
        action="store_true",
        help="Fail if `gitleaks` isn't on PATH (the integrator will run a scoped secret scan).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Offline start: skip gh entirely (requires --default); all git-based BASE "
        "invariants still run. See merge-serialization.md 'No-gh fallback'.",
    )
    parser.add_argument(
        "--mission",
        metavar="NAME",
        help="Refuse to start if this mission (or a playbook it composes) is quarantined "
        "in runtime/quarantine.json (#558), or if --runtime lacks its required capabilities (#586).",
    )
    parser.add_argument(
        "--runtime",
        metavar="PROVIDER",
        help="RPI provider name (e.g. orca, posix, overstory, t3code, ao, superset, auto). "
        "Defaults to $OPEN_FLEET_RUNTIME or $ORCA_FLEET_RUNTIME when set (#586).",
    )
    parser.add_argument(
        "--strict-native-capabilities",
        "--strict-native",
        dest="strict_native",
        action="store_true",
        help="Require mission capabilities to be in the provider's native_capabilities only.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON summary alongside preflight status.",
    )
    args = parser.parse_args(argv)

    runtime_provider = _active_runtime(args.runtime)
    effective_mode = args.mode

    # Capability check (#586): when --runtime (or OPEN_FLEET_RUNTIME /
    # ORCA_FLEET_RUNTIME) is active, validate provider and mission capabilities
    # fail-closed before usage/branch checks so incompatible missions exit 2.
    cap_info: dict[str, Any] | None = None
    if runtime_provider:
        cap_refusal, cap_info = _capabilities_refusal(
            args.mission, runtime_provider, strict_native=args.strict_native
        )
        if cap_refusal:
            if args.json:
                print(json.dumps(cap_info))
            print(f"preflight: ERROR: {cap_refusal}", file=sys.stderr)
            return 2

    # Usage errors are exit 1 (contract: 0=OK, 1=usage/dependency, 2=invariant).
    # _UsageExit1Parser remaps argparse's own SystemExit(2) the same way.
    if effective_mode == "write" and not args.base:
        print("preflight: ERROR: --base is required unless --mode readonly", file=sys.stderr)
        return 1
    if args.offline and not args.default:
        print("preflight: ERROR: --default is required with --offline (no gh to derive it)", file=sys.stderr)
        return 1

    errors: list[str] = []
    warnings: list[str] = []

    # 1. Required binaries. Read-only fleets never touch gh/PRs; offline starts
    #    swap every gh step for its git equivalent (merge-serialization.md).
    required = ("git",) if effective_mode == "readonly" or args.offline else ("git", "gh")
    for binary in required:
        if not _which(binary):
            errors.append(f"missing required binary on PATH: {binary}")
    if effective_mode == "write":
        if args.require_gitleaks and not _which("gitleaks"):
            errors.append("missing required binary on PATH: gitleaks (--require-gitleaks was set)")
        elif not _which("gitleaks"):
            warnings.append("gitleaks not on PATH — integrator secret scan step will be skipped")

    if errors:
        for e in errors:
            print(f"preflight: ERROR: {e}", file=sys.stderr)
        return 1

    # 2. In a git repo, with a gh-visible remote.
    rc, _, _ = _run(["git", "rev-parse", "--git-dir"])
    if rc != 0:
        print("preflight: ERROR: not inside a git repository", file=sys.stderr)
        return 1

    # 2b. Quarantine (#558): a quarantined mission may not start, in either
    #     mode — readonly fleets dispatch missions too. Before the readonly
    #     early return on purpose.
    if args.mission:
        refusal = _quarantine_refusal(args.mission)
        if refusal:
            print(f"preflight: ERROR: QUARANTINED {refusal}", file=sys.stderr)
            return 2

    if effective_mode == "readonly":
        if args.json and cap_info is not None:
            print(json.dumps(cap_info))
        else:
            rt_suffix = f", runtime={cap_info['runtime']}" if cap_info else ""
            print(f"preflight: OK — mode=readonly{rt_suffix} (binary + repo checks only; no BASE/PR invariants)")
        return 0

    if args.offline:
        repo = "(offline — gh skipped)"
    else:
        rc, repo, gh_err = _run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            timeout=_GH_TIMEOUT,
        )
        if rc != 0 or not repo:
            print(
                f"preflight: ERROR: `gh repo view` failed: {gh_err or 'no output'}. "
                "If this host is intentionally offline, rerun with --offline --default <branch> "
                "(gh skipped; all git-based BASE invariants still run).",
                file=sys.stderr,
            )
            return 1

    # 3. Derive default branch if not given.
    # Dependency/config lane (exit 1): gh answered but gave no default branch —
    # nothing invariant-shaped has been checked yet.
    default_branch = args.default or _default_branch_via_gh()
    if not default_branch:
        print("preflight: ERROR: could not derive default branch (pass --default)", file=sys.stderr)
        return 1

    # 4. BASE != DEFAULT_BRANCH (the M-5 guardrail), on CANONICAL names so ref
    #    aliases (`origin/main`, `refs/remotes/origin/main`) cannot slip past.
    canon_base = _canon_branch(args.base)
    canon_default = _canon_branch(default_branch)
    if canon_base == canon_default:
        print(
            f"preflight: ERROR: BASE ({args.base!r} -> {canon_base!r}) is the DEFAULT_BRANCH "
            f"({default_branch!r} -> {canon_default!r}). "
            "Every per-finding PR is merged into BASE; if BASE is the default branch, fixes land "
            "straight on production and bypass both the anti-inflation gate and the human "
            "promotion review. Create a dedicated integration branch (e.g. `<maintainer>/fleet-integration`) "
            "off the current run's fork point and rerun.",
            file=sys.stderr,
        )
        return 2

    # 5. BASE exists AS A BRANCH (tags and raw SHAs are rejected — a PR base must
    #    be a branch, and accepting any rev would weaken the alias guard above).
    if not _branch_exists(canon_base):
        print(
            f"preflight: ERROR: BASE {args.base!r} is not a local or origin branch "
            "(tags and raw SHAs are not accepted as an integration BASE).",
            file=sys.stderr,
        )
        return 2

    # 6. BASE forks from a commit reachable from DEFAULT_BRANCH (guards against a BASE
    #    created off an unrelated history — e.g. a stale branch someone accidentally reused).
    mb = _merge_base(args.base, default_branch)
    if not mb:
        print(
            f"preflight: ERROR: no merge-base between {args.base!r} and {default_branch!r}; "
            "BASE does not appear to fork from the default branch's history.",
            file=sys.stderr,
        )
        return 2

    # 6b. Freshness: with --fork-point, the merge-base must BE this run's fork point —
    #     a stale BASE from an earlier run has a merge-base too, but an older one.
    if args.fork_point:
        rc, fp_sha, _ = _run(["git", "rev-parse", "--verify", f"{args.fork_point}^{{commit}}"])
        if rc != 0:
            print(f"preflight: ERROR: --fork-point {args.fork_point!r} is not a commit.", file=sys.stderr)
            return 1
        if fp_sha.strip() != mb:
            print(
                f"preflight: ERROR: merge-base(BASE, {default_branch}) is {mb[:12]}, not the "
                f"declared fork-point {fp_sha.strip()[:12]} — BASE is stale or reused from an "
                "earlier run. Recreate BASE off the current fork point.",
                file=sys.stderr,
            )
            return 2

    # 7. Same-tip advisory: a freshly created integration branch legitimately shares
    #    the default tip, so this is a warning, not a violation.
    tip_base, tip_default = _tip_sha(args.base), _tip_sha(default_branch)
    if tip_base and tip_default and tip_base == tip_default:
        warnings.append(
            f"BASE tip == default tip ({tip_base[:12]}) — expected for a freshly created "
            "integration branch; confirm BASE is not another alias of the default."
        )

    if warnings:
        for w in warnings:
            print(f"preflight: WARN: {w}", file=sys.stderr)

    print(
        f"preflight: OK — repo={repo}, base={args.base}, default={default_branch}, "
        f"fork_point={mb[:12]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
