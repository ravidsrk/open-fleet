"""Unified-diff parsing, path inventory, hunk coordinates, and change-binding engine (RV-D3).

Extracted from runtime/scripts/verify.py behind a narrow seam (_extract_diff,
_diff_target_paths, _bind_hunks_to_change) while keeping hunk-state grammar and
coordinate extraction private here. Hashed into verify.py's _Transcript.TOOLCHAIN
and run_report.TOOLCHAIN_FILES so a substituted sibling cannot forge a transcript.
"""
import re
import shlex


def _diff_records(diff):
    """One hunk-state grammar for both endpoint inventory and edited coordinates."""
    # split("\n"), never splitlines(): the latter also splits on \r, form feeds and Unicode
    # separators INSIDE a content line, which miscounts the hunk — diffparse.py's grammar, which
    # this is one copy of (2026-10-26 review). A trailing newline yields one empty tail line.
    old_left = new_left = 0
    lines = diff.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if line == r"\ No newline at end of file":
            continue
        if old_left or new_left:
            kind = line[:1]
            if kind not in ("-", "+", " "):
                raise ValueError("incomplete diff hunk")
            old_left -= kind in ("-", " ")
            new_left -= kind in ("+", " ")
            if old_left < 0 or new_left < 0:
                raise ValueError("diff hunk exceeds declared line counts")
        elif line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("malformed hunk header")
            _, ac, _, bc = match.groups()
            old_left, new_left = int(ac or 1), int(bc or 1)
            kind = "hunk"
        else:
            kind = "header"
        yield kind, line
    if old_left or new_left:
        raise ValueError("incomplete diff hunk")


def _iter_diff_target_paths(diff, resolve):
    """Inventory both endpoints, including metadata-only changes and deleted files.

    Ambiguous quoted/space-containing headers fail closed rather than disappearing from scope.
    """
    for kind, line in _diff_records(diff):
        if kind != "header":
            continue
        prefixed = True
        if line.startswith("diff --git "):
            values = shlex.split(line[11:])
            if len(values) != 2:
                raise ValueError("ambiguous diff path header")
        elif line.startswith(("--- ", "+++ ")):
            values = [line[4:].split("\t")[0]]
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            values = [line.split(" ", 2)[2]]
            prefixed = False
        else:
            continue
        for value in values:
            if value == "/dev/null":
                continue
            if value.startswith('"') or "\\" in value:
                raise ValueError("quoted diff paths are not supported; use an unambiguous patch")
            if prefixed and value.startswith(("a/", "b/")):
                value = value[2:]
            _, err = resolve(value)
            if err or not value or value.startswith("-"):
                raise ValueError(f"invalid diff path: {value!r}")
            yield value


def _diff_target_paths(diff, resolve):
    return sorted(set(_iter_diff_target_paths(diff, resolve)))


def _hunk_lines(text, side):
    """Actual edited coordinates, never context. Half-integers identify insertion seams.

    The old side of a mutant and new side of base..head both use head coordinates.
    A replacement binds its removed lines; a pure insertion binds the gap before the next line.
    """
    out, current, old_path = {}, None, None
    old = new = None
    removed, added = [], []

    def flush():
        if current and (removed or added):
            own, other = (removed, added) if side == "-" else (added, removed)
            out.setdefault(current, set()).update(own or [other[0][1] - 0.5])
        removed.clear()
        added.clear()

    for kind, line in _diff_records(text):
        if kind == "header" and line.startswith("diff --git "):
            flush()
            old = new = None
            current = None
        elif kind == "header" and line.startswith("--- "):
            old_path = line[4:].split("\t")[0]
        elif kind == "header" and line.startswith("+++ "):
            flush()
            target = old_path if side == "-" else line[4:].split("\t")[0]
            current = target[2:] if target and target.startswith(("a/", "b/")) else target
            if current and current != "/dev/null":
                out.setdefault(current, set())
        elif kind == "hunk":
            flush()
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("malformed hunk header")
            a, ac, b, bc = match.groups()
            old, new = int(a) + (ac == "0"), int(b) + (bc == "0")
        elif kind == "-":
            removed.append((old, new))
            old += 1
        elif kind == "+":
            added.append((new, old))
            new += 1
        elif kind == " ":
            flush()
            old += 1
            new += 1
    flush()
    # Strip the opposite-side coordinate retained for pure insertion/deletion seams.
    return {path: {x[0] if isinstance(x, tuple) else x for x in lines}
            for path, lines in out.items() if path != "/dev/null"}


def _bind_hunks_to_change(diff, m, resolve, git, hex40_re):
    """A `hand` mutant must touch the lines this unit changed, not merely the same FILE.

    Binding by path alone left a decoy one level down: a production file can carry the criterion
    change AND an unrelated change, and a mutant that only touches the unrelated hunk still goes
    RED under a broad test command while the criterion behaviour stands untouched (PR #308 review).
    """
    base, head = m.get("base_sha"), m.get("head_sha")
    if not (base and head and hex40_re.match(str(base)) and hex40_re.match(str(head))):
        return "the hand mutant cannot be bound to the change without pinned base_sha and head_sha"
    touched = _hunk_lines(diff, "-")
    if set(_diff_target_paths(diff, resolve)) != set(touched):
        return "the hand mutant has a deleted, renamed or mode-only path without bound hunks"
    for path, lines in touched.items():
        code, out = git(["--literal-pathspecs", "diff", "--no-ext-diff", "--no-textconv",
                         "--no-renames", "-U0", f"{base}..{head}", "--", path])
        if code != 0:
            return (f"cannot diff {path} over base_sha..head_sha to bind the hand mutant to the "
                    "change; fail-closed")
        scope = getattr(m, "oracle_scope", None)
        changed = (set(scope["paths"].get(path, [])) if scope else
                   _hunk_lines(out, "+").get(path, set()))
        if not lines:
            return (f"the hand mutant's diff names {path} but carries no hunk for it, so nothing "
                    "says which behaviour it mutates (#280)")
        allowed = changed | {n + offset for n in changed if isinstance(n, int)
                             for offset in (-0.5, 0.5)}
        if not lines <= allowed:
            return (f"the hand mutant touches {path} at line(s) {sorted(lines)[:6]}, and "
                    f"base_sha..head_sha changes line(s) {sorted(changed)[:6] or 'none'} there — "
                    "they do not overlap completely. Mutating an untouched hunk of a changed file is the same "
                    "decoy as mutating an untouched file: the RED comes from behaviour this unit "
                    "did not introduce (#280)")
    return None


def _nc_paths(nc, resolve):
    """`negative_control.paths` — the production paths the revert control restores to base_sha.
    Repo-relative, inside the toplevel, never option-like. Returns (paths, err)."""
    raw = nc.get("paths")
    if raw is None:
        return None, None
    if not (isinstance(raw, list) and raw and all(isinstance(x, str) and x for x in raw)):
        return None, "negative_control.paths must be a non-empty list of repo-relative path strings"
    for path in raw:
        if path.startswith("-"):
            return None, f"refusing option-like path in negative_control.paths: {path}"
        _, err = resolve(path)
        if err:
            return None, f"negative_control.paths: {err}"
    return raw, None


def _extract_diff(text):
    """Pull the unified diff out of a `hand` NC artifact. The diff runs from the first `diff --git`
    or `--- ` header through the last line that still looks like diff body; trailing prose (the
    test output that shows the RED) is dropped."""
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]
    start = next((i for i, ln in enumerate(lines)
                  if ln.startswith("diff --git ") or ln.startswith("--- ")), None)
    if start is None:
        return None
    end = start
    for i in range(start, len(lines)):
        ln = lines[i]
        if (ln.startswith(("diff --git ", "index ", "--- ", "+++ ", "@@", "+", "-", " ",
                           "new file mode", "deleted file mode", "similarity index",
                           "rename from", "rename to", "old mode", "new mode"))
                or ln == r"\ No newline at end of file"
                or ln == ""):
            end = i
        else:
            break
    body = "\n".join(lines[start:end + 1]).rstrip("\n")
    return (body + "\n") if body.strip() else None


def bind(host_ns):
    """Bind narrow host-aware seam wrappers that resolve host globals dynamically."""
    def diff_target_paths(diff):
        return _diff_target_paths(diff, host_ns["_resolve"])

    def bind_hunks_to_change(diff, m):
        return _bind_hunks_to_change(
            diff, m, host_ns["_resolve"], host_ns["_git"], host_ns["HEX40_RE"],
        )

    return diff_target_paths, bind_hunks_to_change
