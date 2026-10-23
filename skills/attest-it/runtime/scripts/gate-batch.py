#!/usr/bin/env python3
"""gate-batch.py — run-close human gates as data, not prose (#419).

The 2026-09-14 run parked maintainer questions in a hand-edited gate-batch.md:
no schema, no state machine, no reminder when a gate sat owed for days. This
tool keeps the same gate semantics (owed/answered/waived/overtaken) but stores
each gate as a typed record in docs/runs/<run>/gate-batch.json. The .md stays
beside it as a rendered VIEW: every mutation re-renders it on save
(`render --check` verifies the two agree), so prose never drifts from the
store. `related`/`blocking` are store-only and never render.

State machine: add creates owed; answer/waive/overtake move owed -> their
status exactly once (re-transitioning is an error, not an overwrite — the
record is history). stale REPORTS gates owed >= N days; it never notifies
anyone (auto-escalation is out of scope). list WARNS (stderr, exit 0) when a
unit manifest cites a gate id the batch does not carry.

Storage: one JSON file per run, docs/runs/<run>/gate-batch.json. Pass --run
<dir> or an explicit --file (tests and scratch batches use --file).

NOT upstream decision-gates: this tool never touches `orca orchestration
gate-create` / `gate-resolve` / `gate-list`. Those block a task inside the
runtime; these gates are LOCAL run-close records — owed questions a run parks
for its maintainer, answered by hand. Same word, two mechanisms; this file is
the local one.
"""
import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

SCHEMA_TAG = "gate-batch/1"
STATUSES = ("owed", "answered", "waived", "overtaken")
TERMINAL = ("answered", "waived", "overtaken")
GATE_ID_RE = re.compile(r"^G[0-9]+$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
# A parked unit cites a gate as "gate-batch.json G<n>" (pre-tooling refs say
# gate-batch.md; both resolve). The id must sit right at the anchor — bare "G3"
# prose elsewhere ("the G3 ASK body") is not a citation. Covered forms:
# "gate-batch.md G3", "gate-batch.md:22 (G2 ...)" (line-anchored), "G1-G4"
# (a range counts every id inside it, not just its endpoints).
CITE_RE = re.compile(r"gate-batch\.(?:md|json)(?::[0-9]+)?\s*\(?\s*"
                     r"(G[0-9]+(?:\s*-\s*G[0-9]+)?)")
CITE_ID_RE = re.compile(r"\bG[0-9]+\b")
CITE_RANGE_RE = re.compile(r"^(G[0-9]+)\s*-\s*(G[0-9]+)$")
REQUIRED_BATCH_KEYS = ("schema", "run_id", "run_title", "intro", "gates",
                       "resolved_by_events")
REQUIRED_GATE_KEYS = ("id", "title", "question", "asked", "status", "answer",
                      "answered", "related", "blocking")


class GateError(Exception):
    """A usage or store error: the CLI prints it and exits 2."""


def repo_root():
    return Path(__file__).resolve().parent.parent.parent


def resolve_batch(run=None, file=None):
    if file:
        return Path(file)
    return repo_root() / "docs" / "runs" / run / "gate-batch.json"


def today_utc():
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(text, field):
    if not isinstance(text, str) or not DATE_RE.match(text):
        raise GateError(f"{field} must be YYYY-MM-DD, got {text!r}")
    try:
        return datetime.date(int(text[0:4]), int(text[5:7]), int(text[8:10]))
    except ValueError:
        raise GateError(f"{field} is not a real date: {text!r}")


def validate_gate(gate):
    if not isinstance(gate, dict):
        raise GateError(f"a gate must be an object, got {gate!r}")
    missing = [k for k in REQUIRED_GATE_KEYS if k not in gate]
    if missing:
        raise GateError(f"gate {gate.get('id', '?')} is missing {missing}")
    extra = sorted(set(gate) - set(REQUIRED_GATE_KEYS))
    if extra:
        raise GateError(f"gate {gate['id']} carries unknown fields {extra}")
    if not isinstance(gate["id"], str) or not GATE_ID_RE.match(gate["id"]):
        raise GateError(f"gate id must look like G1, got {gate['id']!r}")
    for key in ("title", "question"):
        if not isinstance(gate[key], str) or not gate[key].strip():
            raise GateError(f"gate {gate['id']}: {key} must be non-blank prose")
    asked = parse_date(gate["asked"], f"gate {gate['id']} asked")
    if gate["status"] not in STATUSES:
        raise GateError(f"gate {gate['id']}: status {gate['status']!r} "
                        f"is not one of {', '.join(STATUSES)}")
    for key in ("related", "blocking"):
        if (not isinstance(gate[key], list)
                or not all(isinstance(r, str) for r in gate[key])):
            raise GateError(f"gate {gate['id']}: {key} must be a list of refs")
    if gate["status"] == "owed":
        if gate["answer"] is not None or gate["answered"] is not None:
            raise GateError(f"gate {gate['id']} is owed but carries "
                            "answer/answered text")
    else:
        answered = parse_date(gate["answered"], f"gate {gate['id']} answered")
        if answered < asked:
            raise GateError(f"gate {gate['id']}: recorded {answered} "
                            f"precedes asked {asked}")
        if gate["status"] in ("answered", "waived") and not (
                isinstance(gate["answer"], str) and gate["answer"].strip()):
            raise GateError(f"gate {gate['id']}: {gate['status']} needs the "
                            "answer/waiver text recorded (overtaken alone may "
                            "leave it null when the question body says why)")


def validate_batch(data):
    if not isinstance(data, dict):
        raise GateError("the batch file must hold one JSON object")
    missing = [k for k in REQUIRED_BATCH_KEYS if k not in data]
    if missing:
        raise GateError(f"the batch is missing {missing}")
    extra = sorted(set(data) - set(REQUIRED_BATCH_KEYS))
    if extra:
        raise GateError(f"the batch carries unknown fields {extra}")
    if data["schema"] != SCHEMA_TAG:
        raise GateError(f"schema tag is {data['schema']!r}, want {SCHEMA_TAG!r}")
    for key in ("run_id", "run_title"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise GateError(f"batch {key} must be a non-blank string")
    for key in ("intro", "resolved_by_events"):
        if not isinstance(data[key], str):
            raise GateError(f"batch {key} must be a string")
    if not isinstance(data["gates"], list):
        raise GateError("batch gates must be a list")
    seen = set()
    for gate in data["gates"]:
        validate_gate(gate)
        if gate["id"] in seen:
            raise GateError(f"gate {gate['id']} appears twice")
        seen.add(gate["id"])


def load_batch(path):
    path = Path(path)
    if not path.is_file():
        raise GateError(f"no batch at {path} (init one with `init`)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise GateError(f"cannot read {path}: {e}")
    validate_batch(data)
    return data


def _atomic_write_text(path, text):
    """Crash-safe write: the bytes land in a tmp sibling first, and os.replace
    commits them — an interrupt leaves the old file (or nothing), never half
    a write."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def save_batch(path, data):
    validate_batch(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path,
                       json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def next_gate_id(data):
    nums = [int(g["id"][1:]) for g in data["gates"]]
    return f"G{(max(nums) + 1) if nums else 1}"


def find_gate(data, gid):
    for gate in data["gates"]:
        if gate["id"] == gid:
            return gate
    known = ", ".join(g["id"] for g in data["gates"]) or "(no gates yet)"
    raise GateError(f"no gate {gid} in this batch (known: {known})")


def init_batch(path, *, run_id, run_title, intro="", resolved=""):
    path = Path(path)
    if path.exists():
        raise GateError(f"{path} already exists (add gates to it)")
    data = {"schema": SCHEMA_TAG, "run_id": run_id, "run_title": run_title,
            "intro": intro, "gates": [], "resolved_by_events": resolved}
    save_batch(path, data)
    return data


def add_gate(data, *, title, question, gid=None, asked=None, related=(),
             blocking=()):
    gid = gid or next_gate_id(data)
    if not GATE_ID_RE.match(gid):
        raise GateError(f"gate id must look like G1, got {gid!r}")
    if any(g["id"] == gid for g in data["gates"]):
        raise GateError(f"gate {gid} already exists (ids are stable: "
                        "a renumber orphans parked-unit citations)")
    gate = {"id": gid, "title": title, "question": question,
            "asked": asked or today_utc().isoformat(), "status": "owed",
            "answer": None, "answered": None,
            "related": list(related), "blocking": list(blocking)}
    validate_gate(gate)
    data["gates"].append(gate)
    data["gates"].sort(key=lambda g: int(g["id"][1:]))
    return gate


def transition(data, gid, status, text, answered=None):
    if status not in TERMINAL:
        raise GateError(f"cannot transition to {status!r}")
    gate = find_gate(data, gid)
    if gate["status"] != "owed":
        raise GateError(f"gate {gid} is already {gate['status']}: only an "
                        "owed gate moves (the record is history, not a draft)")
    text = (text or "").strip()
    if status in ("answered", "waived") and not text:
        need = "the human's answer" if status == "answered" \
            else "the waiver reason"
        raise GateError(f"{status} gate {gid} needs {need} recorded")
    recorded = answered or today_utc().isoformat()
    if parse_date(recorded, "recorded") < parse_date(gate["asked"], "asked"):
        raise GateError(f"gate {gid}: recorded {recorded} precedes asked "
                        f"{gate['asked']}")
    gate["status"] = status
    gate["answer"] = text or None
    gate["answered"] = recorded
    validate_gate(gate)
    return gate


def list_gates(data, status=None, blocking=None):
    """Gates by status and, optionally, by blocked ref. The close rule waits
    on list(status="owed", blocking=<unit>): every owed blocker whatever its
    age — `stale` is only a reminder report and must never gate a close."""
    if status is not None and status not in STATUSES:
        raise GateError(f"status {status!r} is not one of "
                        f"{', '.join(STATUSES)}")
    return [g for g in data["gates"]
            if (status is None or g["status"] == status)
            and (blocking is None or blocking in g["blocking"])]


def stale_gates(data, days, today=None):
    if days < 1:
        raise GateError(f"--days must be >= 1, got {days}")
    today = today or today_utc()
    stale = []
    for gate in data["gates"]:
        if gate["status"] != "owed":
            continue
        age = (today - parse_date(gate["asked"], "asked")).days
        if age >= days:
            stale.append((gate, age))
    stale.sort(key=lambda pair: pair[0]["asked"])
    return stale


def _expand_cite_token(token):
    """Every id a citation token names: a lone G<n>, or a G<a>-G<b> range
    expanded inclusively — a deleted intermediate inside a cited range must
    still warn, so endpoints alone are never enough."""
    match = CITE_RANGE_RE.match(token.strip())
    if not match:
        return CITE_ID_RE.findall(token)
    lo, hi = sorted((int(match.group(1)[1:]), int(match.group(2)[1:])))
    return [f"G{n}" for n in range(lo, hi + 1)]


def cited_gate_ids(run_dir):
    """Gate ids cited by unit manifests: {id: [manifest, ...]}.

    Only filename-anchored citations count ("gate-batch.json G3", or the
    pre-tooling "gate-batch.md G3") — prose that merely mentions a bare G3
    is not a citation and never warns.
    """
    cited = {}
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        return cited
    for manifest in sorted(run_dir.glob("*-manifest.json")):
        try:
            text = manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for match in CITE_RE.finditer(text):
            for ref in _expand_cite_token(match.group(1)):
                cited.setdefault(ref, [])
                if manifest.name not in cited[ref]:
                    cited[ref].append(manifest.name)
    return cited


def check_citations(data, run_dir):
    """Warnings for manifest citations no gate carries. Warning, not error:
    a dangling ref is a coordinator typo to fix, never a reason to fail a
    close that is otherwise evidence-bound."""
    known = {g["id"] for g in data["gates"]}
    cited = cited_gate_ids(run_dir)
    warnings = []
    for gid in sorted(set(cited) - known):
        manifests = ", ".join(cited[gid])
        warnings.append(f"warning: {manifests} cites gate {gid}, which no "
                        "gate in this batch carries")
    return warnings


ANNOTATION = {"answered": "Answered", "waived": "Waived",
              "overtaken": "Overtaken"}


def render_batch(data):
    """The .md view. Byte-stable: an owed gate renders exactly its heading
    plus its verbatim question, so a freshly migrated batch re-renders the
    original file byte-for-byte; only recorded answer text adds lines."""
    validate_batch(data)
    parts = [f"# Run-close human-gate batch \u2014 "
             f"{data['run_id']} ({data['run_title']})", "", data["intro"]]
    for gate in data["gates"]:
        parts += ["", f"## {gate['id']} \u00b7 {gate['title']}", "",
                  gate["question"]]
        if gate["answer"]:
            parts += ["", f"**{ANNOTATION[gate['status']]} "
                          f"{gate['answered']}:** {gate['answer']}"]
    if data["resolved_by_events"]:
        parts += ["", "## Resolved by events (report only, no ask)", "",
                  data["resolved_by_events"]]
    return "\n".join(parts) + "\n"


def refresh_view(path, data):
    """Rewrite the sibling .md view from the store. Every CLI mutation calls
    this right after saving, so "md is a view" holds without the operator
    remembering a second command."""
    md = Path(path).parent / "gate-batch.md"
    _atomic_write_text(md, render_batch(data))
    return md


def _read_prose(direct, file, stdin_text, field):
    if direct is not None and file is not None:
        raise GateError(f"pass either {field} or {field}-file, not both")
    if file is not None:
        if file == "-":
            return stdin_text
        try:
            return Path(file).read_text(encoding="utf-8")
        except OSError as e:
            raise GateError(f"cannot read {file}: {e}")
    if direct is None:
        raise GateError(f"{field} is required ({field}-file - reads stdin)")
    return direct


def _split_refs(values):
    refs = []
    for value in values or ():
        refs += [r.strip() for r in value.split(",") if r.strip()]
    return refs


def _fmt_list(gate):
    head = (f"{gate['id']} [{gate['status']}] asked {gate['asked']} "
            f"\u00b7 {gate['title']}")
    if gate["status"] != "owed":
        head += f" \u2192 recorded {gate['answered']}"
    if gate["blocking"]:
        head += f" (blocking {', '.join(gate['blocking'])})"
    return head


def _fmt_show(gate):
    lines = [f"{gate['id']} \u00b7 {gate['title']}",
             f"status: {gate['status']} (asked {gate['asked']})"]
    if gate["status"] != "owed":
        lines.append(f"recorded {gate['answered']}: {gate['answer'] or '(no text)'}")
    if gate["related"]:
        lines.append("related: " + ", ".join(gate["related"]))
    if gate["blocking"]:
        lines.append("blocking: " + ", ".join(gate["blocking"]))
    lines += ["", gate["question"]]
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gate-batch.py",
        description="Run-close human gates as typed records (#419). "
                    "The JSON batch is the store; gate-batch.md is rendered. "
                    "NOT upstream decision-gates (orca orchestration "
                    "gate-create/gate-resolve/gate-list): this batch is LOCAL "
                    "to the run.",
        epilog="example: gate-batch.py --run 2026-09-14-clean-sweep-tracker "
               "list --status owed")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--run", metavar="DIR",
                        help="run directory under docs/runs/")
    target.add_argument("--file", metavar="PATH",
                        help="explicit batch JSON path (tests, scratch)")
    # The same flags after the subcommand (SUPPRESS keeps main-parser
    # values unless re-given): `list --run x` and `--run x list` both work.
    store = argparse.ArgumentParser(add_help=False)
    store.add_argument("--run", metavar="DIR", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    store.add_argument("--file", metavar="PATH", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("init", parents=[store],
                        help="start an empty batch for a run",
                        description="Start an empty batch file.",
                        epilog="example: gate-batch.py --run my-run init "
                               "--run-id run_abc --title '2026-09-20 my run'")
    p.add_argument("--run-id", default=None,
                   help="stable run id (default: the --run directory name)")
    p.add_argument("--title", required=True, help="human run name")
    p.add_argument("--intro", default=None, help="standing prose for the batch")
    p.add_argument("--intro-file", default=None, metavar="PATH",
                   help="read --intro from a file (- for stdin)")
    p.add_argument("--resolved", default=None,
                   help="report-only resolved-by-events markdown block")
    p.add_argument("--resolved-file", default=None, metavar="PATH",
                   help="read --resolved from a file (- for stdin)")
    p.add_argument("--force-init-over-md", action="store_true",
                   help="overwrite the sibling gate-batch.md even when it "
                        "already exists (DESTROYS the pre-tooling view: "
                        "back it up first unless its gates are already "
                        "transcribed)")

    p = subs.add_parser("add", parents=[store],
                        help="park a new question (status owed)",
                        description="Park a new question. The id defaults to "
                                    "the next G<n>; pass --id to pin one "
                                    "while migrating an old batch.",
                        epilog="example: gate-batch.py --run my-run add "
                               "--title 'sign the manifest' --question-file - "
                               "--related '#386' --blocking '#386'")
    p.add_argument("--id", default=None, help="gate id, e.g. G1")
    p.add_argument("--title", required=True, help="heading suffix")
    p.add_argument("--question", default=None, help="the full ask")
    p.add_argument("--question-file", default=None, metavar="PATH",
                   help="read --question from a file (- for stdin)")
    p.add_argument("--asked", default=None,
                   help="ask date YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--related", default=[], action="append",
                   help="related issue/PR ref (repeatable, comma-ok)")
    p.add_argument("--blocking", default=[], action="append",
                   help="blocked unit/issue ref (repeatable, comma-ok)")

    p = subs.add_parser("answer", parents=[store],
                        help="record the human's answer (owed -> answered)",
                        description="Record the human's answer on an owed gate.",
                        epilog="example: gate-batch.py --run my-run answer G1 "
                               "--answer 'the vault holds the key'")
    p.add_argument("gid", help="gate id, e.g. G1")
    p.add_argument("--answer", required=True, help="the human's answer")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")

    p = subs.add_parser("waive", parents=[store],
                        help="record a waiver (owed -> waived)",
                        description="Record that the human ruled no answer "
                                    "needed, with the reason.",
                        epilog="example: gate-batch.py --run my-run waive G3 "
                               "--reason 'blind verdict suffices'")
    p.add_argument("gid", help="gate id, e.g. G3")
    p.add_argument("--reason", required=True, help="why no answer is needed")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")

    p = subs.add_parser("overtake", parents=[store],
                        help="record events answering first (owed -> overtaken)",
                        description="Record that events resolved the question "
                                    "before the human replied. The note is "
                                    "optional: when the question body already "
                                    "says what happened, there is nothing "
                                    "to add.",
                        epilog="example: gate-batch.py --run my-run overtake "
                               "G4 --note 'fixtures-plus-oracle merged'")
    p.add_argument("gid", help="gate id, e.g. G4")
    p.add_argument("--note", default=None,
                   help="what overtook the question (may be omitted)")
    p.add_argument("--date", default=None,
                   help="recorded date YYYY-MM-DD (default: today, UTC)")

    p = subs.add_parser("list", parents=[store],
                        help="list gates; warn on dangling manifest citations",
                        description="List gates (all, one status, or one "
                                    "blocked ref). Then scan sibling "
                                    "*-manifest.json files for "
                                    "gate-batch.json G<n> citations and warn "
                                    "on stderr about ids no gate carries.",
                        epilog="example: gate-batch.py --run my-run list "
                               "--status owed --blocking '#386'")
    p.add_argument("--status", default=None, choices=list(STATUSES),
                   help="show only this status (default: all)")
    p.add_argument("--blocking", default=None, metavar="REF",
                   help="show only gates blocking this unit/issue ref "
                        "(e.g. '#386'); with --status owed this is the "
                        "close wait-predicate: every owed blocker, "
                        "whatever its age)")

    p = subs.add_parser("stale", parents=[store],
                        help="report gates owed >= N days (default 7)",
                        description="Report owed gates asked >= N days ago. "
                                    "A report only: exit 0 either way, it "
                                    "notifies nobody.",
                        epilog="example: gate-batch.py --run my-run stale "
                               "--days 3")
    p.add_argument("--days", type=int, default=7,
                   help="flag gates owed this many days or more")
    p.add_argument("--today", default=None,
                   help="act as of YYYY-MM-DD (a testing aid, not a time "
                        "machine: production runs omit it)")

    p = subs.add_parser("show", parents=[store],
                        help="print one gate in full",
                        description="Print one gate: status, refs, and the "
                                    "full question.",
                        epilog="example: gate-batch.py --run my-run show G1")
    p.add_argument("gid", help="gate id, e.g. G1")

    p = subs.add_parser("render", parents=[store],
                        help="regenerate the .md view from the JSON store",
                        description="Regenerate gate-batch.md from the JSON "
                                    "store. The .md is a view, never edited "
                                    "by hand: every mutation re-renders it "
                                    "on save, and render --check verifies "
                                    "the two agree.",
                        epilog="example: gate-batch.py --run my-run render "
                               "--check")
    p.add_argument("--out", default=None, metavar="PATH",
                   help="write here instead of the sibling gate-batch.md "
                        "(- for stdout)")
    p.add_argument("--check", action="store_true",
                   help="exit 1 when the rendered view differs from --out "
                        "(default: the sibling .md)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        run, file = getattr(args, "run", None), getattr(args, "file", None)
        if bool(run) == bool(file):
            raise GateError("pass exactly one of --run DIR and --file PATH")
        path = resolve_batch(run, file)
        wants_stdin = [getattr(args, f, None) for f in
                       ("intro_file", "resolved_file", "question_file")]
        stdin_text = sys.stdin.read() if "-" in wants_stdin else ""
        if args.command == "init":
            run_id = args.run_id or (run if run
                                     else Path(file).parent.name)
            intro = _read_prose(args.intro, args.intro_file, stdin_text,
                                "--intro") if (args.intro is not None
                                               or args.intro_file) else ""
            resolved = _read_prose(args.resolved, args.resolved_file,
                                   stdin_text, "--resolved") \
                if (args.resolved is not None or args.resolved_file) else ""
            sibling = Path(path).parent / "gate-batch.md"
            if sibling.exists() and not getattr(args, "force_init_over_md",
                                                False):
                raise GateError(
                    f"{sibling} already exists (a pre-tooling view holding "
                    "the only gate record): transcribe its gates via "
                    "add/answer/waive/overtake after backing it up first, "
                    "or re-run with --force-init-over-md to destroy it")
            data = init_batch(path, run_id=run_id, run_title=args.title,
                               intro=intro.rstrip("\n"),
                               resolved=resolved.rstrip("\n"))
            refresh_view(path, data)
            print(f"initialized {path}")
            return 0
        data = load_batch(path)
        if args.command == "add":
            question = _read_prose(args.question, args.question_file,
                                   stdin_text, "--question")
            gate = add_gate(data, title=args.title,
                            question=question.rstrip("\n"), gid=args.id,
                            asked=args.asked,
                            related=_split_refs(args.related),
                            blocking=_split_refs(args.blocking))
            save_batch(path, data)
            refresh_view(path, data)
            print(f"added {gate['id']} (owed)")
            return 0
        if args.command in ("answer", "waive", "overtake"):
            status = {"answer": "answered", "waive": "waived",
                      "overtake": "overtaken"}[args.command]
            field = {"answer": "answer", "waive": "reason",
                     "overtake": "note"}[args.command]
            text = getattr(args, field)
            gate = transition(data, args.gid, status, text,
                              answered=args.date)
            save_batch(path, data)
            refresh_view(path, data)
            print(f"{gate['id']} -> {status}")
            return 0
        if args.command == "list":
            for gate in list_gates(data, args.status, args.blocking):
                print(_fmt_list(gate))
            for warning in check_citations(data, path.parent):
                print(warning, file=sys.stderr)
            return 0
        if args.command == "stale":
            today = parse_date(args.today, "--today") \
                if args.today else None
            for gate, age in stale_gates(data, args.days, today):
                print(f"{gate['id']} owed {age} days "
                      f"(asked {gate['asked']}) \u00b7 {gate['title']}")
            return 0
        if args.command == "show":
            print(_fmt_show(find_gate(data, args.gid)))
            return 0
        if args.command == "render":
            out = args.out or str(path.parent / "gate-batch.md")
            rendered = render_batch(data)
            if args.out == "-":
                sys.stdout.write(rendered)
                return 0
            if args.check:
                current = Path(out).read_text(encoding="utf-8") \
                    if Path(out).is_file() else None
                if current != rendered:
                    print(f"{out} is not what the store renders",
                          file=sys.stderr)
                    return 1
                print(f"{out} matches the store")
                return 0
            _atomic_write_text(out, rendered)
            print(f"rendered {out}")
            return 0
    except GateError as e:
        print(f"gate-batch.py: error: {e}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    sys.exit(main())

