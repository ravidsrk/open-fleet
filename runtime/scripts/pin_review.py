#!/usr/bin/env python3
"""pin_review.py — the rug-pull diff for an upstream pack pin bump (#559).

runtime/pins.json pins the worker packs by commit, but a bump used to record
only the new commit: nothing said what changed in the pack's instruction
files or the permissions its skills ask for (Agent Baseline RES-05 — block
unapproved changes to a component's instructions, tool definitions,
requested permissions, or integrity references).

This helper makes the bump review mechanical. Given a clone of the pack and
two commits, it classifies every changed path and emits the review artifact
skeleton the bumper completes:

    pin_review.py --repo <clone> --pack gstack --from <old> --to <new>
    pin_review.py --repo <clone> --pack gstack --to <new>   # baseline inventory

Classes:
    instruction          what an agent will obey: Markdown/prompts anywhere,
                         SKILL.md / AGENTS.md, skills/ trees
    permission-surface   what can grant or widen action: hooks (by directory
                         or by a `hook` name token, e.g. bin/x-hook-check),
                         setup/install scripts, plugin and package manifests,
                         settings, MCP/tool config — and every SKILL.md whose
                         frontmatter `hooks:` or `allowed-tools:` changed
    code                 everything else

The skeleton's verdict line starts UNREVIEWED; a human or coordinator reads
the classified lists (and the instruction diffs behind them) and replaces it.
tests/test_pins.py refuses a pack pin whose current commit has no completed
artifact under docs/research/pin-reviews/, so a bump without the review does
not land. The orca pin is out of scope here — pin-it owns its mechanism drift.

Exits: 0 skeleton written to stdout · 2 usage · 3 cannot evaluate (bad repo
or unresolvable commit). Stdlib-only; git via argv, never a shell line.
"""
import sys

# W3-01: `python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib, so a committed
# sibling named like a stdlib module (json.py, hashlib.py) would BE that module here, and no
# toolchain hash binds it. Drop that entry before any other import (`from __future__` imports too,
# which is why this file has none); `os` is read from sys.modules, loaded at start-up, never
# imported. `python3 -I` does the same from outside; this holds when a caller forgets it.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import datetime
import importlib.util
import re
import subprocess
from pathlib import Path


def _load_gitexec():
    spec = importlib.util.spec_from_file_location(
        "gitexec", Path(__file__).resolve().parent / "gitexec.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load_gitexec()

# `.md.tmpl` is the source a pack renders SKILL.md and its sections from.
INSTRUCTION_SUFFIXES = (".md", ".prompt", ".txt", ".md.tmpl")
PERMISSION_NAMES = {
    "plugin.json", "marketplace.json", "package.json", "settings.json",
    "settings.local.json", "hooks.json", ".mcp.json", "mcp.json",
}
PERMISSION_SUFFIXES = (".toml", ".yaml", ".yml")
# Filename tokens that mark an executable which registers or runs as a hook,
# or an installer that writes settings — a hook script under bin/ or a root
# `setup` is reviewed with the surface, not as code (gstack 47d639ab review).
HOOK_TOKENS = {"hook", "hooks"}
INSTALL_TOKENS = {"setup", "install", "preinstall", "postinstall"}
# Frontmatter keys that register hooks, grant tools, change permission mode, or declare MCP servers (#787).
PERMISSION_KEYS = ("hooks", "allowed-tools", "tools", "permissionMode", "mcpServers")
CLASSES = ("instruction", "permission-surface", "code")


def classify(path: str) -> str:
    parts = [p.lower() for p in Path(path).parts]
    name = parts[-1] if parts else path.lower()
    tokens = set(re.split(r"[-_.]", name))
    if name in PERMISSION_NAMES or "hooks" in parts or name.startswith("hook"):
        return "permission-surface"
    # Never exempt HOOK_TOKENS / INSTALL_TOKENS under test/tests/fixtures paths (#787):
    # an attacker could hide a hook or installer under a test-named directory.
    if tokens & HOOK_TOKENS:
        return "permission-surface"
    if tokens & INSTALL_TOKENS and not re.search(r"\.(md|txt|prompt)(\.tmpl)?$", name):
        return "permission-surface"
    # Slash-command definitions are instructions an agent executes on
    # invocation (commands/*.toml, .gemini/commands/*, .claude/commands/*) —
    # the upstream audit catalogues them as such; they are not config.
    if "commands" in parts:
        return "instruction"
    if name in ("skill.md", "agents.md", "claude.md") or "skills" in parts:
        return "instruction"
    if name.endswith(INSTRUCTION_SUFFIXES):
        return "instruction"
    if name.endswith(PERMISSION_SUFFIXES) and (
        "config" in name or ".claude-plugin" in parts or ".github" in parts
    ):
        return "permission-surface"
    return "code"


def _git(repo: Path, *argv: str) -> str:
    try:
        gitexec.refuse_blocking_files(repo)
        result = subprocess.run(
            gitexec.argv("-C", str(repo), *argv), capture_output=True, text=True,
            timeout=120, env=gitexec.custody_env(), stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as err:
        # A slow on-demand fetch (blobless clone) is a cannot-evaluate like
        # any other git failure — never a traceback with the wrong exit code.
        raise PinReviewError(
            f"git {' '.join(argv[:2])} timed out after {err.timeout}s") from err
    except (OSError, gitexec.GitCustodyRefused) as err:
        raise PinReviewError(f"git {' '.join(argv[:2])} refused: {err}") from err
    if result.returncode != 0:
        raise PinReviewError(f"git {' '.join(argv[:2])} failed: {result.stderr.strip()}")
    return result.stdout


class PinReviewError(Exception):
    pass


def resolve(repo: Path, ref: str) -> str:
    # The ref sits in option position (W2-04): an option is refused, never handed to git.
    if not ref or ref.startswith("-"):
        raise PinReviewError(f"{ref!r} must name a git ref, not an option")
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def changed_paths(repo: Path, old: str | None, new: str) -> list[tuple[str, str]]:
    """(status, path) pairs old..new; old=None inventories the whole tree.

    NUL-separated output throughout: with Git's default quoting, a non-ASCII
    filename arrives wrapped in quotes and its real suffix is lost to the
    classifier. --no-renames so a move lists the deletion and the addition
    separately — classifying only the destination hides a hook leaving the
    permission surface (or entering it).
    """
    if old is None:
        out = _git(repo, "ls-tree", "-r", "-z", "--name-only", new)
        return [("A", name) for name in out.split("\0") if name]
    out = _git(repo, "diff", "--name-status", "-z", "--no-renames", f"{old}..{new}", "--")
    tokens = [t for t in out.split("\0") if t]
    pairs = []
    it = iter(tokens)
    for status in it:
        path = next(it, None)
        if path is None:
            raise PinReviewError("git diff --name-status -z: truncated token stream")
        pairs.append((status[0], path))
    return pairs


def classify_changes(pairs):
    grouped = {klass: [] for klass in CLASSES}
    for status, path in pairs:
        grouped[classify(path)].append(f"{status} {path}")
    return {klass: sorted(items) for klass, items in grouped.items()}


def _frontmatter_lines(text):
    """Lines inside a YAML frontmatter block, or None.

    Strips a leading UTF-8 BOM, tolerates trailing spaces/tabs on `---` fences, and ignores
    `---` lines that occur inside a quoted multiline scalar (#787).
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not lines or lines[0].rstrip(" \t") != "---":
        return None
    quote = None
    for idx in range(1, len(lines)):
        line = lines[idx]
        if quote is None and line.rstrip(" \t") == "---":
            return lines[1:idx]
        i, n = 0, len(line)
        while i < n:
            ch = line[i]
            if quote is None:
                if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                    break
                if ch in ('"', "'") and (i == 0 or line[i - 1] in " \t:[{,"):
                    quote = ch
            elif quote == "'":
                if ch == "'":
                    if i + 1 < n and line[i + 1] == "'":
                        i += 1
                    else:
                        quote = None
            elif quote == '"':
                if ch == "\\" and i + 1 < n:
                    i += 1
                elif ch == '"':
                    quote = None
            i += 1
    return None


def permission_keys(text):
    """Each PERMISSION_KEYS block of a Markdown file's YAML frontmatter, raw."""
    fm_lines = _frontmatter_lines(text)
    if fm_lines is None:
        return {}
    blocks, current = {}, None
    for line in fm_lines:
        # A quoted key ("hooks":) is the same YAML key — and the easy way to
        # slip a grant past an unquoted-only match (PR #573 review).
        top = re.match(r"^([\"']?)([A-Za-z0-9_-]+)\1[ \t]*:", line)
        if top:
            current = top.group(2) if top.group(2) in PERMISSION_KEYS else None
            if current:
                blocks[current] = [line.rstrip()]
        elif current:
            blocks[current].append(line.rstrip())
    return {key: "\n".join(lines) for key, lines in blocks.items()}


def _show(repo: Path, commit: str, path: str) -> str:
    try:
        gitexec.refuse_blocking_files(repo)
        result = subprocess.run(
            gitexec.argv("-C", str(repo), "show", f"{commit}:{path}"),
            capture_output=True, timeout=120, env=gitexec.custody_env(),
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as err:
        raise PinReviewError(f"git show timed out after {err.timeout}s") from err
    except (OSError, gitexec.GitCustodyRefused) as err:
        raise PinReviewError(f"git show refused: {err}") from err
    if result.returncode != 0:
        raise PinReviewError(f"git show {path} failed: "
                             f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout.decode("utf-8", "replace")


def _is_frontmatter_surface_path(path: str) -> bool:
    """SKILL.md, *.md.tmpl, .claude/commands/*.md, and .claude/agents/*.md (#787)."""
    p = Path(path)
    name = p.name.lower()
    if name == "skill.md" or name.endswith(".md.tmpl"):
        return True
    parts = [part.lower() for part in p.parts]
    if name.endswith(".md"):
        for i in range(len(parts) - 2):
            if parts[i] == ".claude" and parts[i + 1] in ("commands", "agents"):
                return True
    return False


def frontmatter_permission_changes(repo: Path, old: str | None, new: str, pairs):
    """Skill, command, agent, and template files whose frontmatter permission keys changed.

    A skill, slash-command, subagent, or template registers hooks, grants tools, changes
    permissionMode, or declares mcpServers in its own frontmatter, so the path classifier alone
    files that widening under `instruction` (gstack 47d639ab, #787). Each such file is listed on
    the permission surface too, naming the keys that moved. A deletion only narrows and is
    already listed by path.
    """
    out = []
    for status, path in pairs:
        if not _is_frontmatter_surface_path(path) or status == "D":
            continue
        after = permission_keys(_show(repo, new, path))
        before = (permission_keys(_show(repo, old, path))
                  if old is not None and status != "A" else {})
        moved = sorted(k for k in set(before) | set(after)
                       if before.get(k) != after.get(k))
        if moved:
            out.append(f"{status} {path} (frontmatter: {', '.join(moved)})")
    return out


def render(pack, repo_url, old, new, grouped, date):
    span = f"`{old}` → `{new}`" if old else f"baseline inventory at `{new}`"
    lines = [
        f"# Pin review — {pack} {new[:12]}",
        "",
        f"Dated snapshot: {date}. Rug-pull review (RES-05) for the `{pack}` pin in",
        f"`runtime/pins.json`: {span}.",
        f"Upstream: {repo_url}",
        "",
        f"Verdict: UNREVIEWED — replace after reading the instruction and",
        "permission-surface changes below (clean | changes-noted: <what>).",
        "",
        "## Changed surface by class",
        "",
    ]
    for klass in CLASSES:
        items = grouped[klass]
        lines.append(f"### {klass} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("- none")
        elif old is not None or len(items) <= 60 or klass == "permission-surface":
            # Bump artifacts list EVERY changed path, however large the bump:
            # the reviewer reads paths, not counts. The permission surface is
            # always listed in full, baselines included.
            lines += [f"- `{item}`" for item in items]
        else:
            # Only a baseline inventory rolls up: thousands of paths would
            # bury the surface the next bump diffs against.
            by_dir = {}
            for item in items:
                top = item.split(" ", 1)[1].split("/", 1)[0]
                by_dir[top] = by_dir.get(top, 0) + 1
            lines.append(f"- {len(items)} files; by top-level directory:")
            lines += [f"  - `{d}/`: {n}" for d, n in sorted(by_dir.items())]
        lines.append("")
    lines += [
        "## Reviewer notes",
        "",
        "Instruction changes read: <which, and what they now ask the agent to do>",
        "Permission-surface changes read: <new tools/hooks/scopes, or none>",
        "",
    ]
    return "\n".join(lines)


VERDICT_LINE = re.compile(
    r"^Verdict: (baseline recorded|clean|changes-noted)\b.*$", re.MULTILINE
)

# The only artifacts allowed to carry the `baseline recorded` verdict: the
# inventories of the initially pinned commits, taken when the review was
# introduced (#559). Every later pin is a BUMP and must review the diff —
# without this fence, running the helper without --from and filling the
# notes would pass a bump with no diff read at all (PR #566 review, P1).
BASELINE_ARTIFACTS = frozenset({
    "addyosmani-be4e44a9fbc5e8df0beaefadbb28bd22ee61cc39.md",
    "gstack-71f6048e.md",
    "mattpocock-3cca18b.md",
})

SPAN = re.compile(r"`([0-9a-f]{7,40})` → `([0-9a-f]{7,40})`")


def artifact_kind_problems(text, filename, pinned_commit):
    """Baseline-vs-bump shape problems for one artifact, or [].

    A baseline artifact (in BASELINE_ARTIFACTS) must be an inventory; any
    other artifact must carry a diff span `old → new` whose new side is
    the pinned commit (prefix-related either way: the pin may abbreviate
    what render resolved, or the reverse). A `baseline recorded` verdict
    outside the baseline set is a bump trying to skip its diff.
    """
    problems = []
    verdict = VERDICT_LINE.search(text)
    is_baseline_verdict = bool(verdict and verdict.group(1) == "baseline recorded")
    span = SPAN.search(text)
    if filename in BASELINE_ARTIFACTS:
        if not is_baseline_verdict:
            problems.append(
                "a baseline artifact must carry the `baseline recorded` verdict")
        return problems
    if is_baseline_verdict:
        problems.append(
            "only the initial inventory artifacts may record a baseline — "
            "a pin bump must review the diff old → new")
    if span is None:
        problems.append(
            "no diff span `old` → `new` — generate with --from <old pin>")
    else:
        new = span.group(2)
        if not (new.startswith(pinned_commit) or pinned_commit.startswith(new)):
            problems.append(
                f"diff span ends at {new}, not the pinned commit {pinned_commit}")
    return problems


def completed_review_problems(text):
    """Why this artifact is not a completed review, or [] if it is.

    The contract tests/test_pins.py enforces: a supported verdict (not the
    skeleton's UNREVIEWED) AND both reviewer-note lines actually filled —
    swapping the verdict word alone is not a review.
    """
    problems = []
    if "UNREVIEWED" in text:
        problems.append("verdict is still the skeleton's UNREVIEWED placeholder")
    elif not VERDICT_LINE.search(text):
        problems.append(
            "no supported verdict line (baseline recorded | clean | changes-noted)")
    for label in ("Instruction changes read:", "Permission-surface changes read:"):
        match = re.search(rf"^{re.escape(label)}[ \t]*(.*)$", text, re.MULTILINE)
        note = match.group(1).strip() if match else ""
        if not note or note.startswith("<"):
            problems.append(f"reviewer note '{label}' is unfilled")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="a clone of the pack")
    parser.add_argument("--pack", required=True, help="the pins.json key (gstack, …)")
    parser.add_argument("--from", dest="old", help="previous pinned commit (omit: baseline)")
    parser.add_argument("--to", required=True, help="new pinned commit")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    try:
        new = resolve(repo, args.to)
        old = resolve(repo, args.old) if args.old else None
        pairs = changed_paths(repo, old, new)
        frontmatter = frontmatter_permission_changes(repo, old, new, pairs)
    except (PinReviewError, OSError) as err:
        print(f"pin_review: {err}", file=sys.stderr)
        return 3
    try:
        origin = _git(repo, "remote", "get-url", "origin").strip()
    except PinReviewError:
        # The URL is display provenance, not a safety input: a clone without
        # an origin still yields a reviewable diff, and the artifact says so.
        origin = "(no origin remote on the reviewed clone)"
    grouped = classify_changes(pairs)
    grouped["permission-surface"] = sorted(grouped["permission-surface"] + frontmatter)
    print(render(args.pack, origin, old, new, grouped,
                 datetime.date.today().isoformat()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
