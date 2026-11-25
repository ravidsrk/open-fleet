#!/usr/bin/env sh
# install.sh — one-command open-fleet install (issue #414).
#
# From a clone:
#   sh scripts/install.sh
# From anywhere (the documented one-command install):
#   git clone https://github.com/ravidsrk/open-fleet.git && cd open-fleet && sh scripts/install.sh
#
# What it does:
#   1. HARD prerequisites: git present, python3 >= 3.11, catalog gates green
#      (scripts/validate.py), every mission symlinked into the skills dir with
#      its playbooks/ and runtime/ references resolving, completion-gate
#      snippet available. Any failure here exits nonzero.
#   2. SOFT prerequisites (warnings only — needed to RUN missions, not to
#      install the catalog): the orca CLI at or above the runtime/pins.json
#      pin, gh present and authenticated, Claude Code present. The orca checks
#      are runtime-aware: with $OPEN_FLEET_RUNTIME / $ORCA_FLEET_RUNTIME naming a
#      non-orca provider they are skipped (missions dispatch through that
#      provider, not the orca CLI); `auto` checks an orca CLI that is present
#      but never warns about an absent one (auto falls back to posix).
#   3. --check re-verifies an existing install without changing anything.
#   4. A shallow clone (git clone --depth 1) is refused up front with the exact
#      remedy (`git fetch --unshallow`): proven missions' run reports pin older
#      commits that a truncated history cannot resolve. Nothing is fetched for you.
#   5. An existing mission link that points into a DIFFERENT live clone is not
#      silently repointed: the install refuses unless --force is given.
#   6. The skills dir and every mission name are OPERANDS of mkdir/ln: an empty or
#      option-shaped (-x) skills dir and a mission directory name outside
#      [A-Za-z0-9._-] (or starting with -) are refused up front, `--` ends every
#      option list, and an unset HOME is a named failure, never a `set -u` abort
#      (W2-05/W5-22).
#
# Exit: 0 installed (warnings allowed) · 1 a hard prerequisite failed.
set -eu

# Physical paths (pwd -P): the verify step compares against realpath, so a logical
# path through a symlinked directory (macOS /tmp -> /private/tmp) would never match.
HERE=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -P -- "$HERE/.." && pwd -P)
SKILLS_DIR=""
SKILLS_DIR_GIVEN=0
MODE="install"
FORCE=0
WARN=0

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --force) FORCE=1 ;;
    --skills-dir=*) SKILLS_DIR="${arg#--skills-dir=}"; SKILLS_DIR_GIVEN=1 ;;
    -h|--help)
      echo "usage: sh scripts/install.sh [--check] [--force] [--skills-dir=DIR]"
      echo "  --force  repoint mission links that currently belong to another open-fleet clone"
      exit 0
      ;;
    *) echo "install.sh: unknown argument $arg" >&2; exit 1 ;;
  esac
done

say() { printf '%s\n' "$1"; }
warn() { WARN=$((WARN + 1)); printf 'WARN: %s\n' "$1"; }
die() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
# A mission directory name becomes an operand of ln and a path under the skills dir.
mission_name_ok() {
  case "$1" in
    -*|*[!A-Za-z0-9._-]*) die "skills/$1 is not a mission directory name (want [A-Za-z0-9._-], not starting with -)" ;;
  esac
}

# The skills dir is an OPERAND of mkdir/ln below; decide it before anything runs.
if [ "$SKILLS_DIR_GIVEN" -eq 0 ]; then
  [ -n "${HOME:-}" ] || die "HOME is not set, so the default skills dir (\$HOME/.claude/skills) has no location — set HOME or pass --skills-dir=DIR"
  SKILLS_DIR="$HOME/.claude/skills"
fi
case "$SKILLS_DIR" in
  "") die "--skills-dir needs a directory (--skills-dir=DIR)" ;;
  -*) die "skills dir '$SKILLS_DIR' starts with '-', so mkdir/ln would read it as an option — pass an absolute path, or prefix a relative one with ./" ;;
esac
# Every mission directory name is judged here, before anything is created or linked, and from
# the directory entry itself: `$(basename …)` strips a trailing newline, so `ok<LF>` passed as `ok`.
for d in "$ROOT"/skills/*/; do
  [ -f "$d/SKILL.md" ] || continue
  m="${d%/}"; m="${m##*/}"
  case "$m" in .*|_*) continue ;; esac
  mission_name_ok "$m"
done

# --- hard prerequisites -------------------------------------------------------
command -v git >/dev/null 2>&1 || die "git not found in PATH (install git first)"
command -v python3 >/dev/null 2>&1 || die "python3 not found in PATH (Python >= 3.11 required)"
# 3.11 is the measured floor (#514): the suite is green on 3.11, 3.12 and 3.13 in CI; 3.10
# compiles but two tests depend on 3.11 interpreter behaviour, so it is not supported.
python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "python3 is $(python3 -V 2>&1); open-fleet requires Python >= 3.11"
[ -d "$ROOT/skills" ] && [ -d "$ROOT/playbooks" ] && [ -d "$ROOT/runtime" ] \
  || die "not an open-fleet checkout: $ROOT lacks skills/, playbooks/ or runtime/"

# --- soft prerequisites (warn, never fail: the catalog installs without them) -
ORCA_MIN="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["orca"]["version"].lstrip("v"))' "$ROOT/runtime/pins.json" 2>/dev/null || true)"
# The active runtime resolves through the SAME code dispatch uses
# (runtime/providers active_provider_name + orca.resolve_orca_binary):
# OPEN_FLEET_RUNTIME over ORCA_FLEET_RUNTIME (a blank/whitespace value falls
# through), trimmed, case-insensitive; `auto` is orca only when the platform's
# resolved Orca binary (ORCA_CLI_COMMAND, orca-dev, orca-ide on Linux, orca
# elsewhere) is on PATH, else posix. Prints "<requested>\t<provider>\t<orca-bin>".
RUNTIME_PROBE="$(python3 -I - "$ROOT" 2>/dev/null <<'PY' || true
import os, sys
pkg = type(sys)("runtime")
pkg.__path__ = [os.path.join(sys.argv[1], "runtime")]
sys.modules["runtime"] = pkg
from runtime.providers import active_provider_name, resolve_orca_binary
from runtime.providers.base import env_get
raw = env_get("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME").lower() or "orca"
try:
    name = active_provider_name()
except Exception:
    name = "unknown"
orca_bin = ""
if name in ("orca", "auto"):
    try:
        orca_bin = resolve_orca_binary()
    except Exception:
        orca_bin = ""
print("\t".join(("_".join(raw.split()), name, orca_bin)))
PY
)"
ACTIVE_RUNTIME="$(printf '%s' "$RUNTIME_PROBE" | awk -F '\t' '{print $1}')"
ACTIVE_PROVIDER="$(printf '%s' "$RUNTIME_PROBE" | awk -F '\t' '{print $2}')"
RESOLVED_ORCA="$(printf '%s' "$RUNTIME_PROBE" | awk -F '\t' '{print $3}')"
ORCA_BIN=""
PROBE_FAILED=0
if [ -z "$ACTIVE_PROVIDER" ]; then
  warn "could not resolve the active runtime through runtime/providers; checking for the orca CLI"
  ACTIVE_RUNTIME=orca
  ACTIVE_PROVIDER=orca
  PROBE_FAILED=1
fi
case "$ACTIVE_RUNTIME:$ACTIVE_PROVIDER" in
  auto:orca) ORCA_EXPECTED=required ;;
  auto:*) ORCA_EXPECTED=auto-posix ;;
  *:orca) ORCA_EXPECTED=required ;;
  *:unknown) ORCA_EXPECTED=unknown ;;
  *) ORCA_EXPECTED=none ;;
esac
if [ "$ORCA_EXPECTED" = required ]; then
  if [ -n "$RESOLVED_ORCA" ]; then
    ORCA_BIN="$(command -v "$RESOLVED_ORCA" 2>/dev/null || true)"
    if [ -z "$ORCA_BIN" ] && [ "$RESOLVED_ORCA" = "orca-ide" ]; then
      # On Linux, /usr/bin/orca is commonly the GNOME screen reader: refuse system paths
      # and GNOME screen-reader scripts without executing them.
      _cand="$(command -v orca 2>/dev/null || true)"
      case "$_cand" in
        ""|/usr/bin/orca|/bin/orca|/usr/sbin/orca|/sbin/orca)
          _cand="" ;;
        *)
          if [ -r "$_cand" ] && head -c 2048 "$_cand" 2>/dev/null \
              | grep -qiE 'orca\.orca|orca\.debug|screen reader|pyatspi|gi\.repository|gnome'; then
            _cand=""
          fi ;;
      esac
      ORCA_BIN="$_cand"
    elif [ -z "$ORCA_BIN" ]; then
      ORCA_BIN="$(command -v orca-ide 2>/dev/null || true)"
    fi
  elif [ "$PROBE_FAILED" -eq 1 ]; then
    ORCA_BIN="$(command -v orca-ide 2>/dev/null || command -v orca 2>/dev/null || true)"
  fi
fi
if [ "$ORCA_EXPECTED" = unknown ]; then
  warn "runtime ${ACTIVE_RUNTIME} is not a registered provider (missions will refuse to dispatch); orca CLI checks skipped"
elif [ "$ORCA_EXPECTED" = none ]; then
  say "runtime ${ACTIVE_RUNTIME}: orca CLI checks skipped (missions dispatch through the ${ACTIVE_PROVIDER} provider)"
elif [ "$ORCA_EXPECTED" = auto-posix ]; then
  say "runtime auto: ${RESOLVED_ORCA:-orca} not in PATH, missions dispatch through the posix provider"
elif [ -n "$ORCA_BIN" ]; then
  ORCA_VER="$("$ORCA_BIN" --version 2>/dev/null | head -n 1 || true)"
  if [ -z "$ORCA_MIN" ]; then
    warn "cannot read the Orca version pin (runtime/pins.json) — unable to verify the Orca floor"
  elif [ -z "$ORCA_VER" ]; then
    warn "orca CLI at $ORCA_BIN returned no version output — unable to verify it meets the catalog pin ${ORCA_MIN}"
  else
    python3 -I - "$ORCA_VER" "$ORCA_MIN" 2>/dev/null <<'PY' || warn "orca CLI reports '${ORCA_VER:-unknown}', below the catalog pin ${ORCA_MIN} (runtime/pins.json); missions may misbehave"
import re, sys
def parts(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    return tuple(map(int, m.groups())) if m else None
have, want = parts(sys.argv[1]), parts(sys.argv[2])
sys.exit(0 if (have and want and have >= want) else 1)
PY
  fi
  # Live readiness (S23): `orca status --json` reports app/ + runtime/ + graph/.
  # Ready means the app runs AND the runtime is reachable AND its state is
  # ready (graph folds into runtime.state upstream: status.ts). SOFT like the
  # version floor above — a hard gate here would refuse headless/CI installs
  # where the app simply is not launched yet. That hardening is PARKED
  # (needs-human policy), not silently added.
  ORCA_STATUS="$("$ORCA_BIN" status --json 2>/dev/null || true)"
  if [ -z "$ORCA_STATUS" ]; then
    warn "orca CLI at $ORCA_BIN answered no \`status --json\`, so readiness could not be determined — start Orca before running missions"
  else
    _status_rc=0
    python3 -I - "$ORCA_STATUS" 2>/dev/null <<'PY' || _status_rc=$?
import json, sys
try:
    doc = json.loads(sys.argv[1])
except Exception:
    sys.exit(2)
r = doc.get("result") if isinstance(doc, dict) else None
if not isinstance(r, dict):
    sys.exit(2)
app = r.get("app") or {}
rt = r.get("runtime") or {}
ready = app.get("running") is True and rt.get("reachable") is True and rt.get("state") == "ready"
sys.exit(0 if ready else 1)
PY
    if [ "$_status_rc" -eq 2 ]; then
      warn "orca CLI at $ORCA_BIN answered an unreadable \`status --json\`, so readiness could not be determined — start Orca before running missions"
    elif [ "$_status_rc" -ne 0 ]; then
      warn "orca CLI at $ORCA_BIN is present but its app/runtime is not ready (\`orca status\` disagrees) — start Orca before running missions"
    fi
  fi
else
  warn "no orca CLI in PATH (missions dispatch through it; install Orca >= ${ORCA_MIN:-unknown} to run them, or set OPEN_FLEET_RUNTIME to another provider)"
fi
if command -v gh >/dev/null 2>&1; then
  gh auth status >/dev/null 2>&1 || warn "gh is present but not authenticated (gh auth login); fleets open PRs per unit"
else
  warn "gh not found in PATH (fleets open PRs per unit; install gh to run them)"
fi
command -v claude >/dev/null 2>&1 || warn "claude CLI not found (needed for the symlinked skills to load)"

# --- install ------------------------------------------------------------------
if [ "$MODE" = "install" ]; then
  # A shallow clone cannot resolve the commits that proven missions' run reports
  # pin, so validate.py would fail on them. Say so before validating, with the
  # exact command — never fetch behind the user's back.
  if [ "$(git -C "$ROOT" rev-parse --is-shallow-repository 2>/dev/null || true)" = "true" ]; then
    die "$ROOT is a shallow clone (git clone --depth …) — run-report pins need full history. Run:
  git -C \"$ROOT\" fetch --unshallow
then re-run: sh scripts/install.sh"
  fi
  say "validating the catalog..."
  python3 -I "$ROOT/scripts/validate.py" || die "scripts/validate.py failed — refusing to install a broken catalog"
  mkdir -p -- "$SKILLS_DIR"
  # Pre-check every destination BEFORE linking anything: a conflict in a
  # later mission must refuse the whole install, not leave a partial one.
  for d in "$ROOT"/skills/*/; do
    [ -f "$d/SKILL.md" ] || continue
    m="${d%/}"; m="${m##*/}"
    case "$m" in .*|_*) continue ;; esac
    mission_name_ok "$m"
    if [ -e "$SKILLS_DIR/$m" ] && [ ! -L "$SKILLS_DIR/$m" ]; then
      die "$SKILLS_DIR/$m exists and is not a symlink (a copy install severs playbook resolution — remove it and re-run)"
    fi
    if [ -L "$SKILLS_DIR/$m" ]; then
      cur="$(python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$SKILLS_DIR/$m")"
      if [ "$cur" != "$ROOT/skills/$m" ]; then
        if [ ! -e "$SKILLS_DIR/$m" ]; then
          warn "$SKILLS_DIR/$m is a dangling link (to $cur) — repointing it at this clone"
        elif [ "$FORCE" -eq 1 ]; then
          warn "$SKILLS_DIR/$m points into another clone ($cur) — repointing it at this clone (--force)"
        else
          die "$SKILLS_DIR/$m already points into another clone ($cur), not $ROOT/skills/$m — re-run with --force to repoint every mission at this clone, or use --skills-dir=DIR"
        fi
      fi
    fi
  done
  n=0
  for d in "$ROOT"/skills/*/; do
    [ -f "$d/SKILL.md" ] || continue
    m="${d%/}"; m="${m##*/}"
    case "$m" in .*|_*) continue ;; esac
    mission_name_ok "$m"
    if [ -e "$SKILLS_DIR/$m" ] && [ ! -L "$SKILLS_DIR/$m" ]; then
      die "$SKILLS_DIR/$m exists and is not a symlink (a copy install severs playbook resolution — remove it and re-run)"
    fi
    ln -sfn -- "$ROOT/skills/$m" "$SKILLS_DIR/$m"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || die "no missions found under $ROOT/skills"
  say "linked $n missions into $SKILLS_DIR"
fi

# --- verify (both modes) ------------------------------------------------------
[ -d "$SKILLS_DIR" ] || die "$SKILLS_DIR does not exist — run without --check first"
n=0
for d in "$ROOT"/skills/*/; do
  [ -f "$d/SKILL.md" ] || continue
  m="${d%/}"; m="${m##*/}"
  case "$m" in .*|_*) continue ;; esac
  mission_name_ok "$m"
  link="$SKILLS_DIR/$m"
  [ -L "$link" ] || die "$link is not a symlink (a copy severs playbook resolution — reinstall)"
  resolved="$(python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$link")"
  [ "$resolved" = "$ROOT/skills/$m" ] || die "$link resolves to $resolved, not $ROOT/skills/$m"
  [ -s "$link/SKILL.md" ] || die "$link/SKILL.md is missing or empty"
  parent="$(python3 -I -c 'import os,sys; print(os.path.dirname(os.path.dirname(sys.argv[1])))' "$resolved")"
  [ -d "$parent/playbooks" ] && [ -d "$parent/runtime" ] \
    || die "$m resolves outside the repo tree ($parent) — playbooks/ and runtime/ do not resolve"
  n=$((n + 1))
done
[ "$n" -gt 0 ] || die "no missions found under $ROOT/skills"
sh "$ROOT/hooks/print-settings-snippet.sh" --check >/dev/null \
  || die "completion-gate snippet unavailable (hooks/print-settings-snippet.sh --check failed)"

say "verified $n missions: symlinks resolve, SKILL.md non-empty, playbooks/ + runtime/ in reach"
if [ "$MODE" = "install" ]; then
  say ""
  say "A symlink install loads no plugin, so wire the completion gate by hand:"
  say "  sh hooks/print-settings-snippet.sh   # merge the output into ~/.claude/settings.json"
  say "Details: docs/install.md"
fi
if [ "$WARN" -gt 0 ]; then
  say ""
  if [ "$MODE" = "install" ]; then
    say "$WARN warning(s): install complete, but missions will not RUN until these clear."
  else
    say "$WARN warning(s): install verifies, but missions will not RUN until these clear."
  fi
fi
