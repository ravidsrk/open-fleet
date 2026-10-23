#!/usr/bin/env python3
"""Drift probe for the Orca pin: has upstream moved past `runtime/pins.json`, and how?

Upstream (stablyai/orca) cuts about a release a day; this catalog re-pins quarterly
(`runtime/orca-pin.md`). Between re-pins nothing said how far the pin had fallen behind, so
the first warning was a field sighting. Three subcommands, each independent:

  latest    network only, no binary. Lists upstream's tags through the GitHub API, keeps the
            stable `vX.Y.Z` ones (no `-rc`, no `mobile-*`), compares the highest to the pin
            and counts the stable tags strictly newer than it. The weekly workflow
            (.github/workflows/upstream-drift.yml) runs this and files an `upstream-drift`
            issue on exit 3.
  capture   binary needed. Dumps the surfaces the last re-pin archived as receipts —
            `agent-context --json`, `--help`, `terminal --help`, and the `orchestration` and
            `orca-cli` guides with their bundled references — into DIR, in the shape of
            docs/runs/2026-09-28-pin-it-500/: agent-context.json, help-root.txt,
            terminal-help.txt, guides/<topic>.md, guides/<topic>.refs.txt,
            guides/<topic>--<reference>.md. Every command is an argv list; no shell.
  diff      compares a capture against a receipts directory. Either naming works on either
            side — the receipts' version-suffixed names map onto the capture's
            (agent-context-1.4.215.json <-> agent-context.json, help-root-1.4.215.txt <->
            help-root.txt, terminal-help-1.4.215.txt <-> terminal-help.txt, guides-1.4.215/
            <-> guides/; several versions in one directory -> the highest; probe-*.json
            receipts are not compared). agent-context compares the SET of command names
            (`commands[].command`, else the joined `path`) and the entries behind them; the
            help texts diff by line; the guides directory compares file by file. Every
            added/removed/changed command and every changed file is named.

Usage
  upstream_probe.py latest [--max-patches N] [--pins PATH] [--tags-json PATH]
                           [--tags-url URL] [--timeout SECONDS] [--json]
  upstream_probe.py capture --out DIR [--timeout SECONDS]
  upstream_probe.py diff --baseline DIR --fresh DIR [--json]

Environment (no secret is ever read from a file)
  GITHUB_TOKEN        optional; sent as `Authorization: Bearer` to lift the API rate limit —
                      over https (or http to loopback) only, never to a rel=next on another
                      origin (that refuses, exit 2) and never across a redirect.
  ORCA_CLI_COMMAND    the CLI executable `capture` runs (one executable, no arguments).
  ORCA_DEV_REPO_ROOT  when set and `orca-dev` is on PATH, `capture` runs `orca-dev`.
                      Otherwise `orca-ide` on Linux, else `orca` — upstream's own resolution
                      order (its skill stubs). Not on PATH is exit 2, never a guess.
  HTTPS_PROXY/NO_PROXY  honored by urllib as usual.

Exit codes (fail-closed: an error is never exit 0)
  0  latest: no re-pin due (drift `none`, or `patch` with patches_behind below --max-patches)
     capture: every surface written · diff: identical
  2  could not run — network or HTTP error, unreadable pins.json, no stable tags, CLI not on
     PATH, a capture command failed or printed no JSON, missing/incomplete directory, usage
  3  latest: re-pin due (`minor`/`major` drift, or patches_behind >= --max-patches)
     diff: drift (a command added/removed/changed, a file changed/added/removed)
"""
from __future__ import annotations

import argparse
import difflib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import orca_cli
except ImportError:  # loaded by file path (tests): the resolver sits beside this script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import orca_cli

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PINS = ROOT / "runtime" / "pins.json"
UPSTREAM_REPO = "stablyai/orca"
TAGS_URL = f"https://api.github.com/repos/{UPSTREAM_REPO}/tags?per_page=100"
MAX_PAGES = 5
DEFAULT_MAX_PATCHES = 10
USER_AGENT = "open-fleet-upstream-probe (runtime/scripts/upstream_probe.py)"
STABLE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
# A bundled-reference name as `skills get <topic> --references` lists it.
REF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DIFF_PREVIEW_LINES = 20

EXIT_OK = 0
EXIT_ERROR = 2
EXIT_DUE = 3

# What `capture` writes and what `diff` compares: capture name, receipt glob (the pinned
# receipts suffix the stem with the witnessed version), and the argv `capture` runs.
SURFACES = {
    "agent-context": ("agent-context.json", "agent-context*.json", ("agent-context", "--json")),
    "help-root": ("help-root.txt", "help-root*.txt", ("--help",)),
    "terminal-help": ("terminal-help.txt", "terminal-help*.txt", ("terminal", "--help")),
}
GUIDES_DIR = "guides"
GUIDE_TOPICS = ("orchestration", "orca-cli")


class ProbeError(Exception):
    """Could not run. The message goes to stderr and the exit is 2 — never 0."""


# --- latest -------------------------------------------------------------------------------

def parse_stable(name):
    """(major, minor, patch) for a stable `vX.Y.Z` tag, else None."""
    match = STABLE_TAG.match(name.strip()) if isinstance(name, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


def fmt(version):
    return "v" + ".".join(str(part) for part in version)


def read_pin(path):
    """`orca.version` from a pins.json; anything unreadable or not `vX.Y.Z` is a ProbeError."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProbeError(f"cannot read pins file {path}: {exc}")
    orca = data.get("orca") if isinstance(data, dict) else None
    version = orca.get("version") if isinstance(orca, dict) else None
    if parse_stable(version) is None:
        raise ProbeError(f"{path}: orca.version is not a stable vX.Y.Z tag: {version!r}")
    return version.strip()


def load_json_file(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProbeError(f"cannot read {path}: {exc}")


def tag_names(payload, source):
    """Tag names from a GitHub tags payload (a list of {name: ...}; bare strings tolerated)."""
    if not isinstance(payload, list):
        raise ProbeError(f"{source}: expected a JSON list of tags, got {type(payload).__name__}")
    names = []
    for entry in payload:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if isinstance(name, str):
            names.append(name)
    return names


def next_link(link_header):
    """The URL carrying rel="next" in a Link header, else None."""
    if not link_header:
        return None
    for part in link_header.split(","):
        pieces = [piece.strip() for piece in part.split(";")]
        url = pieces[0]
        if not (url.startswith("<") and url.endswith(">")):
            continue
        params = {piece.replace(" ", "").lower() for piece in pieces[1:]}
        if params & {'rel="next"', "rel=next", "rel='next'"}:
            return url[1:-1]
    return None


def _origin(url):
    try:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port
    except ValueError as exc:
        raise ProbeError(f"unusable URL {url!r}: {exc}")


def _token_may_ride(url):
    """GITHUB_TOKEN goes over https, or plain http to a loopback host (a local mirror or
    test server) — never in clear text across a network."""
    scheme, host, _port = _origin(url)
    return scheme == "https" or (scheme == "http" and host in ("127.0.0.1", "::1", "localhost"))


def fetch_tags(url, timeout, token=None, max_pages=MAX_PAGES):
    """Tag names from `url`, following rel="next" for at most `max_pages` pages.

    A next link is followed only on the scheme, host and port of the first URL: the
    Link header is the server's text, and following it anywhere carried the Bearer
    token to whatever host it named. The token is also an unredirected header, so an
    HTTP redirect does not forward it either.
    """
    names, seen = [], set()
    origin = _origin(url)
    for _page in range(max_pages):
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        request = urllib.request.Request(url, headers=headers)
        if token and _token_may_ride(url):
            request.add_unredirected_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                body = resp.read()
                link = resp.headers.get("Link")
        except urllib.error.HTTPError as exc:
            hint = " (rate limited? set GITHUB_TOKEN)" if exc.code in (403, 429) else ""
            raise ProbeError(f"HTTP {exc.code} from {url}: {exc.reason}{hint}")
        except urllib.error.URLError as exc:
            raise ProbeError(f"could not reach {url}: {exc.reason}")
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ProbeError(f"could not fetch {url}: {exc}")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProbeError(f"{url} did not return JSON: {exc}")
        names.extend(tag_names(payload, url))
        seen.add(url)
        url = next_link(link)
        if not url or url in seen:
            break
        if _origin(url) != origin:
            raise ProbeError(f"refusing rel=next to another origin: {url}")
    return names


def classify(pin, latest):
    """none | patch | minor | major — by the first component on which `latest` moved past `pin`."""
    if latest <= pin:
        return "none"
    if latest[0] != pin[0]:
        return "major"
    if latest[1] != pin[1]:
        return "minor"
    return "patch"


def assess(pin_version, names):
    """{pin, latest, drift, patches_behind}; `patches_behind` = stable tags strictly newer."""
    pin = parse_stable(pin_version)
    stable = {version for version in map(parse_stable, names) if version is not None}
    if not stable:
        raise ProbeError(f"no stable vX.Y.Z tags among {len(names)} tag(s) — nothing to compare")
    latest = max(stable)
    return {
        "pin": fmt(pin),
        "latest": fmt(latest),
        "drift": classify(pin, latest),
        "patches_behind": sum(1 for version in stable if version > pin),
    }


def re_pin_due(result, max_patches):
    """Minor/major drift always; patch drift once the count reaches the threshold."""
    return result["drift"] in ("minor", "major") or result["patches_behind"] >= max_patches


def cmd_latest(args):
    if args.max_patches < 1:
        raise ProbeError("--max-patches must be at least 1")
    pin_version = read_pin(args.pins)
    if args.tags_json:
        names = tag_names(load_json_file(args.tags_json), args.tags_json)
    else:
        names = fetch_tags(args.tags_url, args.timeout, os.environ.get("GITHUB_TOKEN"))
    result = assess(pin_version, names)
    due = re_pin_due(result, args.max_patches)
    if args.json:
        print(json.dumps(result))
    else:
        verdict = "RE-PIN DUE" if due else "no re-pin due"
        print(f"pin {result['pin']} - upstream {result['latest']} - drift {result['drift']} - "
              f"{result['patches_behind']} stable tag(s) newer than the pin "
              f"(threshold {args.max_patches}) -> {verdict}")
    return EXIT_DUE if due else EXIT_OK


# --- capture ------------------------------------------------------------------------------

def resolve_cli(environ=None, platform=None, which=shutil.which):
    """(command, how) per upstream's resolution order; not on PATH raises, never guesses."""
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    explicit = (environ.get("ORCA_CLI_COMMAND") or "").strip()
    if explicit:
        if which(explicit) is None:
            raise ProbeError(f"ORCA_CLI_COMMAND={explicit!r} is not on PATH "
                             "(it must name one executable, without arguments)")
        return explicit, "ORCA_CLI_COMMAND"
    if environ.get("ORCA_DEV_REPO_ROOT") and which("orca-dev") is not None:
        return "orca-dev", "ORCA_DEV_REPO_ROOT is set and orca-dev is on PATH"
    # The platform default comes from the one resolver every fleet script shares (#510);
    # the two overrides above are re-checked here because `capture` must fail loudly
    # when the named executable is missing, which the resolver deliberately never does.
    name = orca_cli.resolve(env={}, system="Linux" if platform.startswith("linux") else "Other")
    if which(name) is None:
        raise ProbeError(f"{name} is not on PATH — install Orca or set ORCA_CLI_COMMAND")
    return name, "platform default"


def run_cli(cli, argv, timeout):
    """stdout of `cli argv...` (stderr when stdout is empty); a non-zero exit is a ProbeError."""
    cmd = [cli, *argv]
    shown = " ".join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ProbeError(f"timed out after {timeout}s: {shown}")
    except OSError as exc:
        raise ProbeError(f"cannot run {shown}: {exc}")
    if proc.returncode != 0:
        tail = " | ".join((proc.stderr or proc.stdout).strip().splitlines()[-5:])
        raise ProbeError(f"exit {proc.returncode} from {shown}" + (f": {tail}" if tail else ""))
    return proc.stdout if proc.stdout else proc.stderr


def reference_names(text):
    """Names from `skills get <topic> --references` output: one per line, bare or as the
    guide spells them (references/<name>.md); anything else is reported and skipped."""
    names = []
    for raw in text.splitlines():
        line = re.sub(r"^[-*]\s+", "", raw.strip())
        if not line:
            continue
        if line.startswith("references/"):
            line = line[len("references/"):]
        if line.endswith(".md"):
            line = line[:-3]
        if REF_NAME.match(line):
            if line not in names:
                names.append(line)
        else:
            print(f"upstream_probe: ignoring --references line {raw.strip()!r}", file=sys.stderr)
    return names


def write_capture(out, rel, text):
    path = out / rel
    path.write_text(text, encoding="utf-8")
    print(f"wrote {rel} ({len(text.encode('utf-8'))} bytes)")


def cmd_capture(args):
    out = Path(args.out)
    if out.exists() and not out.is_dir():
        raise ProbeError(f"--out {out} exists and is not a directory")
    cli, how = resolve_cli()
    print(f"cli: {cli} ({how})")
    try:
        (out / GUIDES_DIR).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProbeError(f"cannot create {out / GUIDES_DIR}: {exc}")
    for filename, _glob, argv in SURFACES.values():
        text = run_cli(cli, argv, args.timeout)
        if filename.endswith(".json"):
            try:
                json.loads(text)
            except ValueError as exc:
                raise ProbeError(f"{cli} {' '.join(argv)} did not print JSON: {exc}")
        write_capture(out, filename, text)
    for topic in GUIDE_TOPICS:
        write_capture(out, f"{GUIDES_DIR}/{topic}.md",
                      run_cli(cli, ("skills", "get", topic), args.timeout))
        refs_text = run_cli(cli, ("skills", "get", topic, "--references"), args.timeout)
        write_capture(out, f"{GUIDES_DIR}/{topic}.refs.txt", refs_text)
        for name in reference_names(refs_text):
            write_capture(out, f"{GUIDES_DIR}/{topic}--{name}.md",
                          run_cli(cli, ("skills", "get", topic, "--reference", name),
                                  args.timeout))
    return EXIT_OK


# --- diff ---------------------------------------------------------------------------------

def version_key(path):
    """The version suffix as a tuple (agent-context-1.4.215.json -> (1, 4, 215); none -> ())."""
    match = re.search(r"(\d+(?:\.\d+)*)", path.name)
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def locate(directory, kind):
    """The file (or guides directory) for `kind` under `directory`, in either naming; several
    version-suffixed candidates resolve to the highest version. Missing is a ProbeError."""
    directory = Path(directory)
    if kind == "guides":
        matches = [p for p in directory.iterdir()
                   if p.is_dir() and (p.name == GUIDES_DIR or p.name.startswith(GUIDES_DIR + "-"))]
        wanted = GUIDES_DIR + "/"
    else:
        wanted, pattern, _argv = SURFACES[kind]
        matches = [p for p in directory.glob(pattern) if p.is_file()]
    if not matches:
        raise ProbeError(f"{directory}: no {kind} receipt ({wanted} or a version-suffixed one)")
    return max(matches, key=lambda p: (version_key(p), p.name))


def command_entries(doc, source):
    """{command name: entry} from an agent-context document (`commands[].command`, else the
    joined `path`)."""
    commands = doc.get("commands") if isinstance(doc, dict) else doc
    if not isinstance(commands, list):
        raise ProbeError(f"{source}: no `commands` list in the agent-context JSON")
    entries = {}
    for entry in commands:
        if not isinstance(entry, dict):
            raise ProbeError(f"{source}: a command entry is not an object: {entry!r}")
        name = entry.get("command")
        if not (isinstance(name, str) and name.strip()):
            path = entry.get("path")
            if isinstance(path, list) and path and all(isinstance(p, str) for p in path):
                name = " ".join(path)
            else:
                raise ProbeError(f"{source}: a command entry has neither `command` nor `path`")
        entries[name.strip()] = entry
    return entries


def compare_agent_context(base_file, fresh_file):
    base = command_entries(load_json_file(base_file), base_file)
    fresh = command_entries(load_json_file(fresh_file), fresh_file)
    same = set(base) & set(fresh)
    return {
        "baseline_file": base_file.name,
        "fresh_file": fresh_file.name,
        "baseline_count": len(base),
        "fresh_count": len(fresh),
        "added": sorted(set(fresh) - set(base)),
        "removed": sorted(set(base) - set(fresh)),
        "changed": sorted(name for name in same
                          if json.dumps(base[name], sort_keys=True)
                          != json.dumps(fresh[name], sort_keys=True)),
    }


def read_lines(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ProbeError(f"cannot read {path}: {exc}")


def compare_text(base_file, fresh_file):
    """Line diff of two text files: identical, or +/- counts with a bounded preview."""
    base, fresh = read_lines(base_file), read_lines(fresh_file)
    result = {"baseline_file": base_file.name, "fresh_file": fresh_file.name}
    if base == fresh:
        result.update(status="identical", added_lines=0, removed_lines=0, preview=[])
        return result
    body = list(difflib.unified_diff(base, fresh, fromfile=base_file.name,
                                     tofile=fresh_file.name, lineterm="", n=0))[2:]
    result.update(
        status="changed",
        added_lines=sum(1 for line in body if line.startswith("+")),
        removed_lines=sum(1 for line in body if line.startswith("-")),
        preview=body[:DIFF_PREVIEW_LINES],
    )
    return result


def compare_guides(base_dir, fresh_dir):
    base = {p.name: p for p in base_dir.iterdir() if p.is_file()}
    fresh = {p.name: p for p in fresh_dir.iterdir() if p.is_file()}
    same = sorted(set(base) & set(fresh))
    changed = [name for name in same if read_lines(base[name]) != read_lines(fresh[name])]
    return {
        "baseline_dir": base_dir.name,
        "fresh_dir": fresh_dir.name,
        "added": sorted(set(fresh) - set(base)),
        "removed": sorted(set(base) - set(fresh)),
        "changed": changed,
        "identical": len(same) - len(changed),
    }


def _names(items):
    return ", ".join(items) if items else "none"


def cmd_diff(args):
    baseline, fresh = Path(args.baseline), Path(args.fresh)
    for label, directory in (("--baseline", baseline), ("--fresh", fresh)):
        if not directory.is_dir():
            raise ProbeError(f"{label} {directory} is not a directory")
    found = {side: {kind: locate(directory, kind) for kind in (*SURFACES, "guides")}
             for side, directory in (("baseline", baseline), ("fresh", fresh))}
    report = {
        "baseline": str(baseline),
        "fresh": str(fresh),
        "agent_context": compare_agent_context(found["baseline"]["agent-context"],
                                               found["fresh"]["agent-context"]),
        "help_root": compare_text(found["baseline"]["help-root"], found["fresh"]["help-root"]),
        "terminal_help": compare_text(found["baseline"]["terminal-help"],
                                      found["fresh"]["terminal-help"]),
        "guides": compare_guides(found["baseline"]["guides"], found["fresh"]["guides"]),
    }
    ac, guides = report["agent_context"], report["guides"]
    changed_files = [report[key]["fresh_file"] for key in ("help_root", "terminal_help")
                     if report[key]["status"] == "changed"]
    changed_files += [f"{GUIDES_DIR}/{name}" for name in guides["changed"]]
    drift = bool(ac["added"] or ac["removed"] or ac["changed"] or changed_files
                 or guides["added"] or guides["removed"])
    report["drift"] = drift
    if args.json:
        print(json.dumps(report, indent=2))
        return EXIT_DUE if drift else EXIT_OK
    for side in ("baseline", "fresh"):
        names = [found[side][kind].name + ("/" if kind == "guides" else "")
                 for kind in (*SURFACES, "guides")]
        print(f"{side}: {report[side]} -> {', '.join(names)}")
    print(f"agent-context: {ac['baseline_count']} -> {ac['fresh_count']} commands"
          f" - added: {_names(ac['added'])} - removed: {_names(ac['removed'])}"
          f" - changed: {_names(ac['changed'])}")
    for key in ("help_root", "terminal_help"):
        text = report[key]
        if text["status"] == "identical":
            print(f"{text['fresh_file']}: identical")
            continue
        print(f"{text['fresh_file']}: CHANGED (+{text['added_lines']}/-{text['removed_lines']} lines)")
        for line in text["preview"]:
            print(f"    {line}")
    print(f"guides: {guides['identical']} identical - added: {_names(guides['added'])}"
          f" - removed: {_names(guides['removed'])} - changed: {_names(guides['changed'])}")
    if drift:
        print(f"VERDICT: DRIFT - {len(ac['added'])} added / {len(ac['removed'])} removed / "
              f"{len(ac['changed'])} changed command(s); "
              f"{len(changed_files)} changed file(s): {_names(changed_files)}; "
              f"guides added {len(guides['added'])}, removed {len(guides['removed'])}")
        return EXIT_DUE
    print("VERDICT: identical")
    return EXIT_OK


# --- entry point --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="upstream_probe.py",
        description="Drift probe for the Orca pin: latest (network only), capture (binary), "
                    "diff (capture vs receipts). Exits 0 fine, 2 could-not-run, 3 re-pin due/drift.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    latest = sub.add_parser("latest", help="compare upstream's highest stable tag to the pin")
    latest.add_argument("--max-patches", type=int, default=DEFAULT_MAX_PATCHES,
                        help="re-pin is due once this many stable tags sit above the pin "
                             f"(default {DEFAULT_MAX_PATCHES})")
    latest.add_argument("--pins", default=str(DEFAULT_PINS),
                        help="pins.json to read orca.version from (default runtime/pins.json)")
    latest.add_argument("--tags-json", help="read the tags payload from this file, no network")
    latest.add_argument("--tags-url", default=TAGS_URL,
                        help="tags endpoint (default the GitHub API for stablyai/orca)")
    latest.add_argument("--timeout", type=float, default=20.0, help="seconds per request")
    latest.add_argument("--json", action="store_true",
                        help='print {"pin","latest","drift","patches_behind"}')
    capture = sub.add_parser("capture", help="dump the receipt surfaces of the CLI on PATH")
    capture.add_argument("--out", required=True, help="directory to write into")
    capture.add_argument("--timeout", type=float, default=60.0, help="seconds per command")
    diff = sub.add_parser("diff", help="compare a capture against a receipts directory")
    diff.add_argument("--baseline", required=True, help="the pinned receipts directory")
    diff.add_argument("--fresh", required=True, help="a capture directory")
    diff.add_argument("--json", action="store_true", help="print the structured report")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return {"latest": cmd_latest, "capture": cmd_capture, "diff": cmd_diff}[args.cmd](args)
    except ProbeError as exc:
        print(f"upstream_probe: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
