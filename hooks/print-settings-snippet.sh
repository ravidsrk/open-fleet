#!/usr/bin/env sh
# print-settings-snippet.sh — emit the symlink-install completion gate, path resolved.
#
# A `ln -s` install into ~/.claude/skills/ loads no plugin, so ${CLAUDE_PLUGIN_ROOT}
# is unset and hooks/hooks.json never fires: the recommended install path ships
# missions with NO completion gate (issue #262). This prints the same two hooks with
# this clone's absolute path substituted, ready to merge into settings.json.
#
#   sh hooks/print-settings-snippet.sh              # to stdout
#   sh hooks/print-settings-snippet.sh --check      # verify the wired script exists
#
# Exit: 0 ok · 1 the template or the gate script is missing, or python3 is absent.
set -eu

HERE=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -P -- "$HERE/.." && pwd -P)
TEMPLATE="$HERE/settings-snippet.json"
GATE="$ROOT/runtime/scripts/verify-gate.sh"

[ -f "$TEMPLATE" ] || { echo "missing $TEMPLATE" >&2; exit 1; }
[ -x "$GATE" ] || [ -f "$GATE" ] || { echo "missing $GATE" >&2; exit 1; }

if [ "${1:-}" = "--check" ]; then
  [ -x "$GATE" ] || { echo "non-executable $GATE" >&2; exit 1; }
  echo "ok: $GATE exists; snippet would wire it from $ROOT"
  exit 0
fi

# The path is substituted by python3 into the PARSED template, never by sed into its text:
# sed escaping covered `&` and `|` (#382) but not `\` or `"`, and a clone path carrying
# either emitted invalid JSON. Each placeholder-led path is shell-quoted inside the command
# string (the host runs it through a shell, so a space or `$` in the path would split or
# expand), then json.dumps encodes the string — both layers escaped by their own encoder.
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to emit the snippet" >&2; exit 1; }
python3 -I - "$TEMPLATE" "$ROOT" <<'PY'
import json, re, shlex, sys

template, root = sys.argv[1], sys.argv[2]
with open(template, encoding="utf-8") as fh:
    data = json.load(fh)


def resolve(value):
    if isinstance(value, dict):
        return {k: resolve(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"__OPEN_FLEET_ROOT__(\S*)", lambda m: shlex.quote(root + m.group(1)), value)
    return value


print(json.dumps(resolve(data), indent=2, ensure_ascii=False))
PY
