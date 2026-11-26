#!/usr/bin/env python3
"""
Generate shields.io endpoint-badge JSON from repo state, so the README badges
never drift as missions and tests are added.

Writes:
  docs/assets/badges/missions.json  — count of skills/<name>/ mission dirs
  docs/assets/badges/tests.json     — source inventory of `def test_*` definitions under tests/;
                                      no test execution or pass/fail result
  docs/missions/<name>.md      — the "Activation load" callout, measured by
                                 scripts/validate.py's transitive_load (issue #276)

The README references these via a shields ENDPOINT badge
(https://img.shields.io/endpoint?url=<raw>/docs/assets/badges/<name>.json), and the
version badge reads .claude-plugin/plugin.json directly via a shields DYNAMIC
badge — so no count lives in hand-written prose or in the badge markup.

`scripts/validate.py` calls `check()` and fails CI if a committed file is stale
(someone added a mission without regenerating). Run this to refresh:

    python3 scripts/gen-badges.py                    # write every surface a PR keeps current
    python3 scripts/gen-badges.py --check            # exit 1 if any of those is stale
    python3 scripts/gen-badges.py --release          # the release cut: also the test count
    python3 scripts/gen-badges.py --check --release  # the cut's check: the test count too

The test count is the one exception (CI speed and bookkeeping change). Every PR changed it, so
every PR rewrote docs/assets/badges/tests.json and conflicted with every other open PR. It is now the
inventory AT THE LAST RELEASE: only `--release` writes it, the release cut runs that, and the
README badge is labelled "at last release", so between releases it shows an older number under a
label that says so, never a stale one presented as current. Between releases CI holds it to its
shape (an "N in source" inventory, never a pass/fail claim) and nothing more.
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

import ast
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
TESTS_DIR = ROOT / "tests"
BADGES_REL = "docs/assets/badges"
BADGES_DIR = ROOT / BADGES_REL
# Where the badges lived until the root clean-up moved assets/ under docs/: a release cut before
# that move holds its tests badge here, so the last-release check reads it at this path.
LEGACY_BADGES_REL = "assets/badges"

GUIDES_DIR = ROOT / "docs" / "missions"
# The callout sits directly under the Autonomy one in every mission guide.
LOAD_CALLOUT_RE = re.compile(r"(?m)^> \*\*Activation load:\*\* .*$")
AUTONOMY_CALLOUT_RE = re.compile(r"(?m)^> \*\*Autonomy:\*\* .*$")
LOAD_ROUND = 100  # tokens — small doc edits must not churn every mission guide


def _validate_module():
    """Load scripts/validate.py lazily.

    validate.py loads THIS module inside check_badge_freshness(); loading it back
    at import time would recurse. Inside a function, each side only ever executes
    the other's module body once.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("_validate", ROOT / "scripts" / "validate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def activation_loads() -> dict:
    """{mission: rounded token estimate} for every mission guide callout."""
    v = _validate_module()
    return {
        name: round(tokens / LOAD_ROUND) * LOAD_ROUND
        for name, tokens in v.load_report()
    }


def load_callout(mission: str, tokens: int) -> str:
    # #525: the number alone says nothing to a person; the share of a 200k-token context does.
    share = round(tokens / 200_000 * 100)
    return (
        f"> **Activation load:** ~{tokens:,} tokens — this SKILL.md plus every playbook and "
        f"runtime doc its Composes/rides clause makes mandatory, about {share}% of a 200k-token "
        f"context before the first dispatch "
        f"([why it is measured](../../ARCHITECTURE.md#instruction-budget))"
    )


def mission_count() -> int:
    return sum(
        1
        for d in SKILLS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").exists()
    )


def test_count(tests_dir: Path | None = None) -> int:
    """Test definitions, PARSED rather than matched.

    A regex over the text counted `def test_thing():` inside a fixture string too, and this
    suite is full of them — a test about test files embeds test files, so tests/ contains
    test sources as data (`BASE_TEST` in test_floor_guard.py is one). The badge is a public
    inventory, so it counts what Python would call a test function and nothing that merely
    reads like one (#334 review).

    A file that does not parse is a real problem, not something to count around: it raises.
    """
    total = 0
    for f in sorted((TESTS_DIR if tests_dir is None else tests_dir).glob("test_*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        total += sum(1 for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name.startswith("test_"))
    return total


def badge(label: str, message: str, color: str) -> dict:
    # shields.io endpoint schema (https://shields.io/badges/endpoint-badge)
    return {"schemaVersion": 1, "label": label, "message": message, "color": color}


def compute() -> dict:
    missing = [d.name for d in (SKILLS_DIR, TESTS_DIR) if not d.is_dir()]
    if missing:
        raise RuntimeError(
            f"cannot compute badges: missing director{'ies' if len(missing) > 1 else 'y'} "
            + ", ".join(f"{m}/" for m in missing)
        )
    return {
        "missions.json": badge("missions", str(mission_count()), "1f6feb"),
        "tests.json": badge("test functions", f"{test_count()} in source", "6e7781"),
    }


def check_guides() -> list[str]:
    """Stale/missing Activation load callouts in docs/missions/*.md."""
    errors = []
    if not GUIDES_DIR.is_dir():
        return [f"docs/missions/ missing at {GUIDES_DIR}"]
    for mission, tokens in activation_loads().items():
        guide = GUIDES_DIR / f"{mission}.md"
        if not guide.is_file():
            errors.append(f"docs/missions/{mission}.md missing — every mission needs a guide")
            continue
        text = guide.read_text(encoding="utf-8")
        want = load_callout(mission, tokens)
        found = LOAD_CALLOUT_RE.search(text)
        if not found:
            errors.append(
                f"docs/missions/{mission}.md has no Activation load callout "
                "— run scripts/gen-badges.py"
            )
        elif found.group(0) != want:
            errors.append(
                f"docs/missions/{mission}.md Activation load is stale "
                f"(want ~{tokens:,} tokens) — run scripts/gen-badges.py"
            )
    return errors


def write_guides() -> None:
    for mission, tokens in activation_loads().items():
        guide = GUIDES_DIR / f"{mission}.md"
        if not guide.is_file():
            print(f"skip docs/missions/{mission}.md: no guide")
            continue
        text = guide.read_text(encoding="utf-8")
        want = load_callout(mission, tokens)
        if LOAD_CALLOUT_RE.search(text):
            new_text = LOAD_CALLOUT_RE.sub(lambda _m, w=want: w, text, count=1)
        else:
            m = AUTONOMY_CALLOUT_RE.search(text)
            if not m:
                print(f"skip docs/missions/{mission}.md: no Autonomy callout to anchor to")
                continue
            new_text = text[: m.end()] + "\n" + want + text[m.end():]
        if new_text != text:
            guide.write_text(new_text, encoding="utf-8")
            print(f"wrote docs/missions/{mission}.md: ~{tokens:,} tokens")


# --- ARCHITECTURE.md's activation-load table -----------------------------------------
# It was written by hand and drifted 150-280 tokens within a day of being published (#303) —
# and again during the work that fixed it, by which point the ORDERING had changed too
# (clean-sweep was the heaviest mission; ship-it is). A table a human retypes is a claim with
# no mechanism, which is the shape this catalog exists to refuse.
ARCH = ROOT / "ARCHITECTURE.md"
ARCH_BEGIN = "<!-- BEGIN GENERATED: activation-load — scripts/gen-badges.py -->"
ARCH_END = "<!-- END GENERATED: activation-load -->"
ARCH_BLOCK_RE = re.compile(
    re.escape(ARCH_BEGIN) + r".*?" + re.escape(ARCH_END), re.S)


def load_table() -> str:
    """The generated block: every mission at or above the three-heaviest mark, plus headroom."""
    v = _validate_module()
    rows = v.load_report()
    cap = v.MISSION_MAX_LOAD_TOKENS
    lines = [ARCH_BEGIN,
             "",
             "| Mission | Activation load | Headroom to the cap |",
             "|---|---|---|"]
    for name, tokens in rows[:3]:
        lines.append(f"| `{name}` | ~{round(tokens / LOAD_ROUND) * LOAD_ROUND:,} | "
                     f"~{round((cap - tokens) / LOAD_ROUND) * LOAD_ROUND:,} |")
    lightest, light_tokens = rows[-1]
    lines += [
        "",
        f"The cap is **{cap:,}**. The lightest mission, `{lightest}`, is "
        f"~{round(light_tokens / LOAD_ROUND) * LOAD_ROUND:,}, so the whole catalog sits in a "
        f"~{round((rows[0][1] - light_tokens) / LOAD_ROUND) * LOAD_ROUND:,}-token band.",
        ARCH_END,
    ]
    return "\n".join(lines)


def check_architecture() -> list[str]:
    if not ARCH.is_file():
        return [f"{ARCH.name} missing at {ARCH}"]
    text = ARCH.read_text(encoding="utf-8")
    found = ARCH_BLOCK_RE.search(text)
    if not found:
        return [f"{ARCH.name} has no generated activation-load block — run scripts/gen-badges.py"]
    if found.group(0) != load_table():
        return [f"{ARCH.name} activation-load table is stale — run scripts/gen-badges.py"]
    return []


def write_architecture() -> None:
    if not ARCH.is_file():
        print(f"skip {ARCH.name}: missing")
        return
    text = ARCH.read_text(encoding="utf-8")
    if not ARCH_BLOCK_RE.search(text):
        print(f"skip {ARCH.name}: no generated block markers to fill")
        return
    new_text = ARCH_BLOCK_RE.sub(lambda _m: load_table(), text, count=1)
    if new_text != text:
        ARCH.write_text(new_text, encoding="utf-8")
        print(f"wrote {ARCH.name}: activation-load table")


# --- README.md's proof-status sentence -------------------------------------------------
# It named two missions by hand and was stale within a week of the third promotion (#512): a
# sentence a human retypes about which missions hold which tier is the same shape as the
# activation-load table above. The block lists every mission by tier, read from the SKILL
# frontmatter, so a promotion rewrites it and `--check` fails until it is regenerated.
README = ROOT / "README.md"
README_BEGIN = "<!-- BEGIN GENERATED: proof-status — scripts/gen-badges.py -->"
README_END = "<!-- END GENERATED: proof-status -->"
README_BLOCK_RE = re.compile(re.escape(README_BEGIN) + r".*?" + re.escape(README_END), re.S)
TIERS = ("external-run", "self-run", "doctrine-only")


def _grammar():
    """The catalog's one frontmatter reader (runtime/scripts/_catalog_grammar.py), by path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_catalog_grammar", ROOT / "runtime" / "scripts" / "_catalog_grammar.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def proof_tiers() -> dict[str, list[str]]:
    """{tier: [mission, ...]} read from every SKILL.md frontmatter; unknown tiers raise.

    Read with the shared frontmatter reader. This used `text.split("---")[1]`, so a `---` inside
    a description ended the "frontmatter" early, the proof tier vanished, and the RuntimeError
    crashed validate.py before its quarantine gate ran (2026-10-23 review, §5).
    """
    tiers: dict[str, list[str]] = {tier: [] for tier in TIERS}
    parse = _grammar().parse_frontmatter
    for d in sorted(SKILLS_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith((".", "_")) or not (d / "SKILL.md").exists():
            continue
        data, _err = parse((d / "SKILL.md").read_text(encoding="utf-8"))
        meta = (data or {}).get("metadata")
        proof = meta.get("proof") if isinstance(meta, dict) else None
        if not isinstance(proof, str) or proof not in tiers:
            raise RuntimeError(f"skills/{d.name}/SKILL.md: no legal metadata.proof tier")
        tiers[proof].append(d.name)
    return tiers


def _join(names: list[str]) -> str:
    quoted = [f"`{n}`" for n in names]
    if len(quoted) <= 1:
        return "".join(quoted)
    return ", ".join(quoted[:-1]) + " and " + quoted[-1]


def proof_block() -> str:
    tiers = proof_tiers()
    parts = []
    for tier in ("external-run", "self-run"):
        if tiers[tier]:
            verb = "reads" if len(tiers[tier]) == 1 else "read"
            parts.append(f"{_join(tiers[tier])} {verb} `{tier}`")
    if parts:
        sentence = ("Today " + "; ".join(parts) + "; every other mission reads `doctrine-only`")
    else:
        sentence = "Today every mission reads `doctrine-only`"
    absent = [tier for tier in ("external-run", "self-run") if not tiers[tier]]
    if absent:
        sentence += "; no mission reads " + " or ".join(f"`{t}`" for t in absent) + " yet"
    return "\n".join([README_BEGIN, f"**{sentence}.**", README_END])


def check_readme() -> list[str]:
    if not README.is_file():
        return [f"{README.name} missing at {README}"]
    text = README.read_text(encoding="utf-8")
    found = README_BLOCK_RE.search(text)
    if not found:
        return [f"{README.name} has no generated proof-status block — run scripts/gen-badges.py"]
    try:
        want = proof_block()
    except RuntimeError as err:  # a check reports; it never takes the caller's later gates down
        return [str(err)]
    if found.group(0) != want:
        return [f"{README.name} proof-status sentence is stale — run scripts/gen-badges.py"]
    return []


def write_readme() -> None:
    if not README.is_file():
        print(f"skip {README.name}: missing")
        return
    text = README.read_text(encoding="utf-8")
    if not README_BLOCK_RE.search(text):
        print(f"skip {README.name}: no generated proof-status markers to fill")
        return
    new_text = README_BLOCK_RE.sub(lambda _m: proof_block(), text, count=1)
    if new_text != text:
        README.write_text(new_text, encoding="utf-8")
        print(f"wrote {README.name}: proof-status sentence")


# Between releases the test badge must still read as an inventory, never a verdict.
TESTS_BADGE = "tests.json"
TESTS_MESSAGE_RE = re.compile(r"^[0-9]+ in source$")
# A release row's commit reaches `git show` as part of an argument: only a full commit name may.
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")


def tests_badge_shape(have) -> list[str]:
    """Errors when the committed tests badge is not an "N in source" inventory badge.

    The between-releases check: the number may be the last release's, but the label, colour
    and wording are the generator's, so a hand edit to "2 passing" or a green colour fails.
    """
    want = badge("test functions", "0 in source", "6e7781")
    if not isinstance(have, dict):
        return [f"{BADGES_REL}/{TESTS_BADGE} is not a badge object"]
    wrong = sorted(k for k in want if k != "message" and have.get(k) != want[k])
    wrong += sorted(set(have) - set(want))
    if not TESTS_MESSAGE_RE.match(str(have.get("message", ""))):
        wrong.append("message")
    if wrong:
        return [f"{BADGES_REL}/{TESTS_BADGE} is malformed ({', '.join(wrong)}: have "
                f"{have.get('message')!r}) — the release cut regenerates it: "
                "python3 scripts/gen-badges.py --release"]
    return []


def last_release_badge_errors(root: Path = ROOT) -> list[str]:
    """Errors when the committed tests badge is not, byte for byte, the last release's own.

    The README labels it "at last release" (PR #670), so between releases it must equal the badge
    at the cut commit docs/releases.json names. While a cut is being prepared, the cut writes a
    new one: then it must be, byte for byte, the badge `--release` writes from this tree's own
    tests/ (2026-10-27 security audit, W6-08: a `preparing` row used to switch the check off, so
    a PR that merely claimed a cut could commit any number). An unreadable release commit is an
    error, never a pass, and so is one that is not a full 40-hex commit name (W6-09: it is part of
    `git show`'s argv, where `--output=<path>` would be read as an option).
    """
    try:
        data = json.loads((root / "docs" / "releases.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        return [f"docs/releases.json: unreadable ({err})"]
    if not isinstance(data, dict):
        return ["docs/releases.json: expected a JSON object"]
    rel = f"{BADGES_REL}/{TESTS_BADGE}"
    if data.get("preparing"):
        return cut_badge_errors(root)
    releases = data.get("releases")
    if not releases:
        return []
    if not isinstance(releases, list):
        return ["docs/releases.json: 'releases' must be a list"]
    last = releases[-1]
    commit = last.get("commit") if isinstance(last, dict) else None
    tag = last.get("tag") if isinstance(last, dict) else None
    if not isinstance(commit, str) or not FULL_SHA_RE.fullmatch(commit):
        return [f"docs/releases.json: the last release's commit {commit!r} is not a full 40-hex "
                "commit name, so its badge is not read"]
    if not isinstance(tag, str) or not tag:
        return ["docs/releases.json: the last release is missing a 'tag' string"]
    # The cut's own badge path: today's, or the pre-move one for a release cut before the move.
    for src in (rel, f"{LEGACY_BADGES_REL}/{TESTS_BADGE}"):
        shown = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{src}"],
                               capture_output=True)
        if not shown.returncode:
            break
    if shown.returncode:
        return [f"cannot read {tag}'s {rel} at {commit[:12]} (a shallow clone? "
                f"fetch the release commit): {shown.stderr.decode(errors='replace').strip()[:200]}"]
    try:
        have = (root / rel).read_bytes()
    except OSError as err:
        return [f"{rel}: unreadable ({err})"]
    if have != shown.stdout:  # bytes, not parsed JSON: a reformat or a reorder is a change too
        def message(raw):
            try:
                return json.loads(raw).get("message")
            except (ValueError, AttributeError):
                return "unparseable"
        return [f"{rel} is not byte for byte {tag}'s ({commit[:12]}): it says "
                f"{message(have)!r} where the release says {message(shown.stdout)!r} — restore it "
                f"with: git show {commit}:{src} > {rel}"]
    return []


def cut_badge_errors(root: Path = ROOT) -> list[str]:
    """Errors unless the committed tests badge is the one the release cut writes from this tree.

    The bytes `write(include_tests=True)` would put there: today's count of test functions under
    tests/, nothing else.
    """
    rel = f"{BADGES_REL}/{TESTS_BADGE}"
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return [f"a cut is being prepared, but there is no tests/ to count for {rel}"]
    count = test_count(tests_dir)
    want = (json.dumps(badge("test functions", f"{count} in source", "6e7781"), indent=2)
            + "\n").encode("utf-8")
    try:
        have = (root / rel).read_bytes()
    except OSError as err:
        return [f"{rel}: unreadable ({err})"]
    if have != want:
        try:
            said = json.loads(have).get("message")
        except (ValueError, AttributeError):
            said = "unparseable"
        return [f"{rel} says {said!r}, but a cut in preparation carries its own count, "
                f"'{count} in source' — run: python3 scripts/gen-badges.py --release"]
    return []


def check(include_test_count: bool = True) -> list[str]:
    """Return a list of stale-artifact errors (empty if everything committed is current).

    include_test_count=False is the between-releases check validate.py runs: tests.json is held
    to its shape, not to today's count, which only the release cut writes.
    """
    errors = []
    try:
        wanted = compute()
    except RuntimeError as err:
        return [str(err)]
    for name, want in wanted.items():
        path = BADGES_DIR / name
        if not path.exists():
            errors.append(f"{BADGES_REL}/{name} missing — run scripts/gen-badges.py")
            continue
        try:
            have = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            errors.append(f"{BADGES_REL}/{name}: invalid JSON ({err})")
            continue
        if name == TESTS_BADGE and not include_test_count:
            errors += tests_badge_shape(have)
        elif have != want:
            fix = " --release" if name == TESTS_BADGE else ""
            errors.append(
                f"{BADGES_REL}/{name} is stale (have {have.get('message')!r}, "
                f"want {want.get('message')!r}) — run scripts/gen-badges.py{fix}"
            )
    return errors + check_guides() + check_architecture() + check_readme()


def write(include_tests: bool = True) -> None:
    """Refresh every generated surface; include_tests=False leaves the release's test count."""
    BADGES_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in compute().items():
        if name == TESTS_BADGE and not include_tests:
            print(f"kept {BADGES_REL}/{name}: the count at the last release "
                  "(the release cut rewrites it with --release)")
            continue
        (BADGES_DIR / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {BADGES_REL}/{name}: {data['message']}")
    write_guides()
    write_architecture()
    write_readme()


if __name__ == "__main__":
    # argparse, not `"--check" in sys.argv`: under the old test a typo'd `--chek` in CI
    # REWROTE the committed badges instead of checking them (#353).
    parser = argparse.ArgumentParser(
        prog="gen-badges.py",
        description="Regenerate the endpoint badges; --check verifies freshness, writing nothing.",
    )
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed badges differ from a fresh computation")
    parser.add_argument("--release", action="store_true",
                        help="the release cut: include the test count (tests.json), which "
                             "pull requests leave at the last release's number")
    parser.add_argument("--check-last-release", action="store_true",
                        help="fail unless the committed tests badge is the last release's own")
    args = parser.parse_args()
    if args.check_last_release:
        errs = last_release_badge_errors()
        for e in errs:
            print(e, file=sys.stderr)
        sys.exit(1 if errs else 0)
    if args.check:
        errs = check(include_test_count=args.release)
        for e in errs:
            print(e, file=sys.stderr)
        sys.exit(1 if errs else 0)
    write(include_tests=args.release)
