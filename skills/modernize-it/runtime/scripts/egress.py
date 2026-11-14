#!/usr/bin/env python3
"""Content-free, hash-chained receipts for everything the fleet sends off-repo.

The run-close integrity inventory hashes what the fleet PRODUCED. Nothing
records what it SENT. This ledger is the second half: one line per off-repo
write the fleet performs -- opening a PR, posting a comment, closing an issue,
triggering a deploy, creating a schedule -- appended BEFORE the send.

Status, stated first because it bounds what this is worth today: doctrine now names it —
merge-serialization.md requires every coordinator off-repo write to be preceded by
``egress.py write … &&`` (#368) — but no automated sink calls it yet beyond merge_queue.py,
which writes this receipt itself before each merge it sends (#599). Every other receipt is
written by a coordinator that follows the policy by hand. Read every sentence below as what it
records once called, not as a guarantee a daemon enforces.

Threat model, stated because it bounds what this is worth even then: the
ledger is forensic observability, not an exfiltration control. It records ATTEMPTED
egress so an accident is auditable afterwards. Anything with a shell can send
without a receipt; the point is that the fleet's own sinks cannot do so
silently.

Record (format v2: one canonical JSON object per line, mode 0600)::

    {"v": 2, "id", "ts", "sink", "host", "payload_class", "bytes",
     "payload_sha256", "consent", "prev"}

* **Where.** ``<repository root>/.orca/egress.jsonl`` -- the root is the nearest directory at or
  above the working directory holding ``.git``, so a send from a subdirectory lands in the same
  ledger; outside a repository the default refuses, and so does a root nested in another
  repository unless it is a linked worktree of it (git's back-link in ``.git/worktrees/<name>``
  agreeing; its own ledger is then named on stderr): a planted or vendored ``.git`` never moves it
  silently. ``--ledger``, ``$OPEN_FLEET_EGRESS_LEDGER`` or ``$ORCA_EGRESS_LEDGER`` name another
  file, and ``write`` then says so on stderr (as it does when the path resolves through a symlink,
  or names a nested root's ledger): a receipt never lands elsewhere silently. Only the
  ledger's own directory is created, never a tree above it. And ``verify`` never passes on no
  receipts (no ledger file, or an empty one: exit 4) unless the caller says none were expected.
* **Content-free.** Never the payload text: a sha256 of the exact bytes sent
  and a byte count, and a ``payload_class`` that describes the KIND of thing
  sent ("pr-body", "issue-comment"). ``payload_sha256`` is null when a
  subprocess owns the bytes and the fleet never saw them. Text fields are printable ASCII on
  every line, legacy ones included, ``consent`` written now names a grant (letters, digits,
  `` ._:/#()@+,=-``), and everything printed has its control characters escaped.
* **Every byte bound.** ``id`` is the sha256 of the record's canonical serialisation without
  ``id`` (fixed key order, ``","``/``":"`` separators, ASCII escapes), and a line must BE the
  canonical serialisation of exactly these keys: an extra key, a re-spaced line, a string where
  ``bytes`` is an integer, a blank line or a missing final newline is refused, on the last line as
  on any other. ``prev`` is the sha256 of the previous raw line (``""`` on line 1), so any edit
  to an earlier line breaks every later one.
* **Anchors, because a chain only proves continuity with A genesis.** A ledger deleted and
  rewritten from scratch links perfectly to its own new genesis (#312), and every receipt written
  since the last anchor can be rewritten with a recomputed ``id``. So an anchor is kept where the
  writer cannot reach it and handed back to ``verify``: the head digest ``head`` prints (run
  close records it), and the ``id`` every ``write`` prints to its caller -- either names one line
  byte for byte, and with it everything before it. ``--expect-ancestor`` (repeatable) requires
  each anchored line still in the chain; ``--expect-head`` requires the ledger to end there.
  Unanchored, the output says so rather than reading as a clean bill.
* **Fail-closed on write.** A sink that cannot write its receipt must not
  send. ``write`` exits 3 in that case, so the caller's ``&&`` stops. It reads the ledger through
  the descriptor it holds locked, verifies every line exactly as ``verify`` does (a ledger the
  verifier would refuse is refused before the send, not discovered at close), appends, and
  fsyncs the file -- and on first creation its directory -- before printing the id.
* **Consent is a field, not a vibe.** Every receipt names the standing grant
  that authorizes the send; ``grants`` verifies the chain, with ``verify``'s anchors, then lists
  them so a human can see what the fleet believes it is allowed to do. Without an anchor it says
  UNANCHORED: a receipt written since the last anchor can be rewritten consistently.

Migration: a ledger written before v2 (no ``"v"`` key) still verifies while each such line is
exactly what the v1 writer produced -- its keys, its canonical bytes, its types and its v1 ``id``
-- which binds every byte of it too. v1 lines are accepted only as a prefix: the first v2 receipt
chains onto the last v1 line, and a v1 line after a v2 one is refused. A legacy line the v1 writer
could not have produced (an extra key, re-spaced JSON) was never bound and now reads as TAMPER.

Subcommands
    write    verify, append one receipt, print its id (an anchor for that receipt)
    verify   recompute the whole chain, check any anchors
    head     verify, then print the chain head digest to anchor off the writer
    grants   verify (and any anchors), then list the distinct consents, with sink/host and use counts

Exit codes
    0  ok (``verify``: the chain is intact, or holds no receipts and the caller said none were expected)
    2  usage -- a missing or malformed argument
    3  fail-closed: the receipt could not be written, the ledger fails verification, or a
       ``verify`` anchor (``--expect-head`` / ``--expect-ancestor``) did not match. Never treat a 3
       as permission to send.
    4  ``verify`` found no receipts (no ledger file, or an empty one): never a pass unless the
       caller said none were expected (``--allow-empty``, or ``--expect-head "(empty)"``).

How to wire
    Every off-repo write the coordinator itself performs is preceded by
    ``egress.py write ... && <the send>`` -- the ``&&`` is the fail-closed
    coupling, since exit 3 stops the send. ``--payload-file`` hashes the exact
    bytes about to go out (a PR body written to a file first), streamed, so a later
    dispute compares hashes rather than memories. Per-worker network egress is
    NOT covered here and cannot be without a proxy: that stays a sandbox-policy
    requirement for the disposable lane, stated rather than claimed. At run
    close, ``verify`` runs beside the integrity inventory and the two together
    answer "what did this run produce, and what left the machine".

    Example: ``egress.py write --sink pr-open --host github.com
    --payload-class pr-body --payload-file /tmp/body.md --consent
    grant:pr-open-on-base && gh pr create --body-file /tmp/body.md``
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAIL_CLOSED = 3
EXIT_NO_RECEIPTS = 4

DEFAULT_LEDGER = ".orca/egress.jsonl"
PRIMARY_LEDGER_ENV = "OPEN_FLEET_EGRESS_LEDGER"
LEDGER_ENV = "ORCA_EGRESS_LEDGER"
FORMAT_VERSION = 2
# Field order is fixed so a record has exactly one canonical line and `id` is reproducible.
FIELDS = ("ts", "sink", "host", "payload_class", "bytes", "payload_sha256", "consent", "prev")
TEXT_FIELDS = ("sink", "host", "payload_class", "consent")
KEYS = {1: ("id",) + FIELDS, FORMAT_VERSION: ("v", "id") + FIELDS}
MAX_FIELD_BYTES = 512
READ_CHUNK = 1 << 20
# Printable ASCII, no leading or trailing space: nothing a terminal interprets, one way to spell it.
TEXT_PATTERN = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?")
# A consent names a standing grant ("grant:pr-open-on-base", "run-2026-09-14:base-writes", or the
# merge queue's "wip-curve run X (#604): merges only to Y"): never control bytes, quotes or a shell
# metacharacter.
CONSENT_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._:/#()@+,=-]*[A-Za-z0-9._:/#()@+,=-])?")
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _inert(text):
    """`text` with every control, format or separator character escaped (\\x1b, \\u2028): what
    egress.py prints is never a terminal command, whatever a field, a path or a reason holds
    (2026-10-27 re-attack, W5-04)."""
    return "".join(c if c == " " or unicodedata.category(c)[0] not in "CZ"
                   else (f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}") for c in str(text))


def _print(*parts, **kwargs):
    print(*(_inert(part) for part in parts), **kwargs)


class EgressError(Exception):
    """Fail-closed condition: the receipt could not be written, or the ledger cannot be trusted."""


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _repositories(start=None):
    """(root, outer): the nearest directory at or above `start` (default: the working directory)
    holding a `.git` entry -- a linked worktree's `.git` file included -- and the nearest one above
    THAT, or None for either."""
    here = Path(os.path.abspath(start or os.getcwd()))
    found = [d for d in (here, *here.parents) if os.path.lexists(d / ".git")]
    return (found[0] if found else None), (found[1] if len(found) > 1 else None)


def repo_root(start=None):
    return _repositories(start)[0]


def _read_small(path):
    """A small regular text file's stripped content, never through a symlink; None otherwise."""
    try:
        fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, 4096).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def _linked_worktree_of(root, outer):
    """True when `root` is a linked worktree of `outer` (`git worktree add`): its `.git` is a file
    naming a directory directly under `outer`'s own `.git/worktrees/`, and that directory's
    `gitdir` -- git's back-link -- names this `.git` again. The text of a `.git` file alone is
    no proof: one planted in a subdirectory could name any path there (W5-03)."""
    gitfile, admin = root / ".git", outer / ".git" / "worktrees"
    if outer.joinpath(".git").is_symlink():
        return False
    text = _read_small(gitfile)
    if not text or not text.startswith("gitdir:"):
        return False
    target = Path(text[len("gitdir:"):].strip())
    target = Path(os.path.realpath(target if target.is_absolute() else root / target))
    if target.parent != Path(os.path.realpath(admin)) or not target.is_dir():
        return False
    back = _read_small(target / "gitdir")
    if not back:
        return False
    back = Path(back) if Path(back).is_absolute() else target / back
    return os.path.realpath(back) == os.path.realpath(gitfile)


def default_ledger(start=None):
    """(absolute path, where it came from) of the repository's own ledger for `start` (default:
    the working directory), or EgressError when it has none: outside a repository, or under a
    `.git` nested in another repository that is not a linked worktree of it. merge_queue.py
    picks its default here too, so a queue run from a subdirectory receipts where the close looks."""
    root, outer = _repositories(start)
    if root is None:
        raise EgressError(f"no repository at or above {os.path.abspath(start or os.getcwd())} (no .git): the default ledger is "
                          f"<repository root>/{DEFAULT_LEDGER}; run from inside the repository, or name the "
                          f"ledger with --ledger or ${PRIMARY_LEDGER_ENV}")
    if outer is not None:
        if not _linked_worktree_of(root, outer):
            raise EgressError(f"the nearest repository root {root} is nested inside the repository {outer} (a "
                              "submodule, a vendored repository or a planted .git): refusing to pick a ledger "
                              f"silently; run from {outer}, or name the ledger with --ledger or "
                              f"${PRIMARY_LEDGER_ENV}")
        return root / DEFAULT_LEDGER, f"the default of linked worktree {root}, inside the repository {outer}"
    return root / DEFAULT_LEDGER, "the repository default"


def resolve_ledger(explicit=None):
    """(absolute ledger path, where it came from). The default is the repository's own ledger,
    never one relative to wherever the command happens to run (W5-03), and never a ledger a
    `.git` below the repository moved silently: a nested root that is not a linked worktree of
    the repository around it (a submodule, a vendored repository, a planted `.git`) refuses."""
    if explicit:
        return Path(os.path.abspath(explicit)), "--ledger"
    for var in (PRIMARY_LEDGER_ENV, LEDGER_ENV):
        env = os.environ.get(var)
        if env:
            return Path(os.path.abspath(env)), f"${var}"
    return default_ledger()


def ledger_path(explicit=None):
    return resolve_ledger(explicit)[0]


def _routing_note(path, source):
    """Why `path` is not the repository's own ledger, or None when it is. The ledger itself is
    never a symlink (it is opened O_NOFOLLOW); its directory being one routes it just as well.
    An explicit path is compared with the ledger the DEFAULT would pick, not with the nearest
    root's: naming the ledger of a planted `.git` is said like any other route (W5-03)."""
    via_link = os.path.islink(path.parent)
    if source == "the repository default" and not via_link:
        return None
    if source.startswith("the default of linked worktree") and not via_link:
        return f"egress: receipt written to {path}: {source}, not to that repository's ledger"
    try:
        default, default_source = default_ledger()
    except EgressError:
        default, default_source = None, None
    if default == path and default_source == "the repository default" and not via_link:
        return None
    real = os.path.realpath(path)
    where = f"{path} ({source}" + (f", its directory a symlink to {os.path.dirname(real)}" if via_link else "") + ")"
    if default is None:
        other = "no repository ledger to compare (the default refuses here)"
    elif default_source == "the repository default":
        other = f"not the repository ledger {default}"
    else:
        other = f"{default_source}, not that repository's ledger"
    return f"egress: receipt written to {where}; {other}"


# A ts is ISO-8601 to the second (optional fraction) with an explicit UTC offset, the shape
# `now` writes. It was the one free-text field never checked, and the v1 id joins `k=v` with
# newlines: a ts carrying "\nsink=..." could make two different records hash alike.
TS_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)")


def valid_ts(value):
    """The ts if it is a real ISO-8601 instant in TS_PATTERN's shape, else raise ValueError."""
    if not isinstance(value, str) or not TS_PATTERN.fullmatch(value):
        raise ValueError(f"ts must be ISO-8601 like 2026-01-02T03:04:05Z, got {value!r}")
    # The whole value must name an instant: a 2026-02-30 date or a +99:99 offset
    # matches the shape and is still not one (fromisoformat reads `Z` on 3.11+).
    datetime.fromisoformat(value)
    return value


def canonical(obj):
    """The one serialisation a receipt has: insertion order, no spaces, ASCII escapes."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _version(record):
    return FORMAT_VERSION if record.get("v") == FORMAT_VERSION and type(record.get("v")) is int else 1


def record_id(record):
    """sha256 binding every field of the record but `id`, chain position included.

    v2 hashes the canonical serialisation of {"v", FIELDS...}. A legacy (v1) record hashes
    newline-joined `k=v` lines, unambiguous only while no value carries a line break and each
    field has its one type -- the reader refuses any line where either fails."""
    if _version(record) == FORMAT_VERSION:
        return sha256_hex(canonical({"v": FORMAT_VERSION, **{k: record.get(k) for k in FIELDS}}))
    return sha256_hex("\n".join(f"{k}={json_scalar(record.get(k))}" for k in FIELDS))


def canonical_line(record):
    """The exact bytes (without the newline) the writer of the record's version produced."""
    if _version(record) == FORMAT_VERSION:
        return canonical({"v": FORMAT_VERSION, "id": record.get("id"), **{k: record.get(k) for k in FIELDS}})
    return canonical({"id": record.get("id"), **{k: record.get(k) for k in FIELDS}})


def json_scalar(value):
    return "" if value is None else str(value)


def require_field(value, name, grant_shape=True):
    """`value` if it is a receipt text field: non-empty printable ASCII on one line, and, for a
    consent written now (`grant_shape`), a grant's name."""
    if not isinstance(value, str) or not value.strip():
        raise EgressError(f"receipt requires a non-empty {name}")
    if "\n" in value or "\r" in value:
        raise EgressError(f"receipt {name} may not contain a newline (one receipt, one line)")
    if len(value.encode("utf-8", "surrogatepass")) > MAX_FIELD_BYTES:
        raise EgressError(f"receipt {name} exceeds {MAX_FIELD_BYTES} bytes")
    if not TEXT_PATTERN.fullmatch(value):
        raise EgressError(f"receipt {name} must be printable ASCII with no leading or trailing space: {value!r}")
    if grant_shape and name == "consent" and not CONSENT_PATTERN.fullmatch(value):
        raise EgressError(f"receipt consent must name a grant (letters, digits and ` ._:/#()@+,=-`, starting "
                          f"with a letter or digit, e.g. grant:pr-open-on-base): {value!r}")
    return value


def _is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def _field_problem(record, version):
    """Why a record's fields are not ones its version's writer could have written, or None."""
    try:
        valid_ts(record["ts"])
    except ValueError:
        return "ts is not an ISO-8601 instant with an offset"
    # The text rule holds on every line, legacy ones included: a v1 consent carrying terminal
    # escapes verified and `grants` printed them raw (2026-10-27 re-attack, W5-04). Only the
    # grant shape is v2's, since the v1 writer took prose consents.
    for name in TEXT_FIELDS:
        try:
            require_field(record[name], name, grant_shape=version == FORMAT_VERSION)
        except EgressError as err:
            return str(err)
    if type(record["bytes"]) is not int or record["bytes"] < 0:
        return "bytes is not a non-negative integer"
    if record["payload_sha256"] is not None and not _is_sha256(record["payload_sha256"]):
        return "payload_sha256 is neither null nor a sha256"
    if not _is_sha256(record["id"]):
        return "id is not a sha256"
    return None


def _line_problem(raw, record, previous_raw):
    """Why one ledger line is not a receipt the writer produced at this position, or None."""
    if not isinstance(record, dict) or not isinstance(record.get("prev"), str):
        return "unparseable line or missing prev"
    if record["prev"] != ("" if previous_raw is None else sha256_hex(previous_raw)):
        return "prev does not match the previous raw line"
    if "v" in record and _version(record) != FORMAT_VERSION:
        return f"unknown format version {record['v']!r}"
    keys = KEYS[_version(record)]
    if set(record) != set(keys):
        extra, missing = sorted(set(record) - set(keys)), sorted(set(keys) - set(record))
        return ("unknown key(s) " + ", ".join(extra) if extra else "missing key(s) " + ", ".join(missing)) + \
            " — a receipt holds exactly its fields, so every byte of it is bound"
    if any(isinstance(record.get(k), str) and ("\n" in record[k] or "\r" in record[k]) for k in FIELDS):
        return "a field carries a line break (ambiguous id encoding)"
    if why := _field_problem(record, _version(record)):
        return why
    if raw != canonical_line(record):
        return "the line is not the canonical serialisation of its record (a byte no hash binds)"
    if record["id"] != record_id(record):
        return "id does not match the record's own fields"
    return None


def scan(data):
    """Verify a ledger's raw bytes: (receipts, broken_line, reason, lines_read).

    `receipts` is [(lineno, raw, record)] for every line up to the first broken one. The whole
    file is the chain: each line is a canonical receipt, newline-terminated, with no blank line
    and no v1 receipt after a v2 one."""
    if not data:
        return [], None, None, 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        lineno = data[:err.start].count(b"\n") + 1
        return [], lineno, f"not valid UTF-8 ({err.reason} at byte {err.start})", data.count(b"\n") + 1
    parts = text.split("\n")
    total = len(parts) - 1 if parts[-1] == "" else len(parts)
    receipts, previous_raw, seen_v2 = [], None, False
    for lineno, raw in enumerate(parts[:-1], 1):
        if not raw:
            return receipts, lineno, "an empty line (every byte of the ledger belongs to a receipt)", total
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if why := _line_problem(raw, parsed, previous_raw):
            return receipts, lineno, why, total
        if _version(parsed) == FORMAT_VERSION:
            seen_v2 = True
        elif seen_v2:
            return receipts, lineno, "a legacy (v1) receipt after a v2 one: only the v2 writer appends", total
        receipts.append((lineno, raw, parsed))
        previous_raw = raw
    if parts[-1] != "":
        return receipts, total, ("the last line has no terminating newline (a torn write, or bytes appended "
                                 "after the last receipt)"), total
    return receipts, None, None, total


def _read_all(fd):
    """Every byte of the ledger, read through the descriptor the caller holds (and has locked)."""
    chunks, offset = [], 0
    while chunk := os.pread(fd, READ_CHUNK, offset):
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _same_file(path, st):
    """Refuse unless `path` still names the inode `st` describes: the receipt must land in, and
    chain onto, the ledger the name names -- not a file swapped in or out beside the lock (W5-02)."""
    try:
        now_st = os.stat(path, follow_symlinks=False)
    except OSError as err:
        raise EgressError(f"receipt ledger {path} vanished while it was being written: {err}") from err
    if (now_st.st_dev, now_st.st_ino) != (st.st_dev, st.st_ino):
        raise EgressError(f"receipt ledger {path} was replaced while it was being written; no receipt is "
                          "on the ledger that name now names")


def _fsync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _open_for_append(path):
    """(fd, created): the ledger opened read-write for append, never through a symlink. Creates the
    ledger's own directory (0700) when it is missing, and never anything above it."""
    flags = os.O_RDWR | os.O_APPEND | O_NOFOLLOW | O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)  # never waits on a FIFO
    try:
        return os.open(path, flags), False
    except FileNotFoundError:
        pass
    parent = path.parent
    if not os.path.lexists(parent):
        try:
            os.mkdir(parent, stat.S_IRWXU)
        except FileExistsError:
            pass  # a concurrent writer made it first
        except FileNotFoundError as err:
            raise EgressError(f"the ledger's directory {parent} does not exist and neither does its parent: "
                              "egress.py creates the ledger's own directory, never a tree above it") from err
        else:
            _fsync_dir(parent.parent)
    try:
        return os.open(path, flags | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR), True
    except FileExistsError:
        return os.open(path, flags), False


def write_receipt(path, sink, host, payload_class, consent, nbytes=0, payload_sha256=None, ts=None):
    """Append one chained receipt. Raises EgressError on any failure (fail closed)."""
    path = Path(path)
    if ts is not None:
        try:
            valid_ts(ts)
        except ValueError as err:
            raise EgressError(str(err)) from err
    if type(nbytes) is not int or nbytes < 0:
        raise EgressError("receipt bytes must be a non-negative integer")
    record = {
        "ts": ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sink": require_field(sink, "sink"),
        "host": require_field(host, "host"),
        "payload_class": require_field(payload_class, "payload_class"),
        "bytes": nbytes,
        "payload_sha256": payload_sha256,
        "consent": require_field(consent, "consent"),
    }
    if payload_sha256 is not None and not _is_sha256(payload_sha256):
        raise EgressError("payload_sha256 must be 64 lowercase hex characters or absent")
    fd = None
    try:
        # O_NOFOLLOW: a ledger path that is a symlink is refused rather than followed, so a
        # planted link cannot redirect receipts into another file (2026-10-26 review); the
        # opened inode must be a regular file for the same reason.
        fd, created = _open_for_append(path)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EgressError(f"receipt ledger {path} is not a regular file")
        # All cooperating writers hold this inode's lock from the read to the fsync, and the read
        # is through this same descriptor: what `prev` chains to is what the append extends.
        fcntl.flock(fd, fcntl.LOCK_EX)
        _same_file(path, st)
        data = _read_all(fd)
        receipts, broken, reason, _total = scan(data)
        if broken is not None:
            raise EgressError(f"{path}:{broken} fails verification ({reason}); refusing to chain a receipt "
                              "onto a ledger the verifier refuses. Repair it, and record why, before sending")
        record["prev"] = sha256_hex(receipts[-1][1]) if receipts else ""
        record = {"v": FORMAT_VERSION, **record}
        record["id"] = record_id(record)
        line = (canonical_line(record) + "\n").encode("ascii")
        try:
            view = memoryview(line)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        except OSError:
            try:
                os.ftruncate(fd, len(data))  # no torn line left for every later write to refuse
            except OSError:
                pass  # the original error is the one to report
            raise
        if created:
            _fsync_dir(path.parent)
        _same_file(path, st)
    except EgressError:
        raise
    except OSError as err:
        raise EgressError(f"receipt could not be written to {path}: {err}") from err
    finally:
        if fd is not None:
            os.close(fd)
    return record


def load_ledger(path):
    """(exists, receipts, broken_line, reason, lines_read), read under a shared lock so a write in
    progress is never seen half-done. A missing ledger is an empty chain that does not exist.
    Opened O_NONBLOCK: a FIFO at the ledger's path opens at once and is refused as not a regular
    file (fail-closed, exit 3), where a blocking open waited forever in `verify`, `head` and
    `grants` (re-attack of e281e130)."""
    try:
        fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return False, [], None, None, 0
    except OSError as err:
        raise EgressError(f"{path} is unreadable (a symlinked ledger is refused): {err}") from err
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise EgressError(f"{path} is not a regular file")
        fcntl.flock(fd, fcntl.LOCK_SH)
        data = _read_all(fd)
    except OSError as err:
        raise EgressError(f"{path} is unreadable: {err}") from err
    finally:
        os.close(fd)
    return (True, *scan(data))


def read_ledger(path):
    """[(lineno, raw, record)] of a ledger that verifies; EgressError naming the first broken line."""
    _exists, receipts, broken, reason, _total = load_ledger(path)
    if broken is not None:
        raise EgressError(f"{path}:{broken} — {reason}")
    return receipts


def head_digest(path):
    """sha256 of the ledger's LAST raw line — the value to anchor off the writer (#312).

    Empty string for an empty chain. This is the only thing a wholesale rewrite cannot reproduce:
    the chain it writes is internally perfect, starting at its own genesis with every link correct,
    but it is a DIFFERENT chain and so has a different head."""
    lines = read_ledger(path)
    return sha256_hex(lines[-1][1]) if lines else ""


def verify_ledger(path):
    """Recompute the chain. Returns (ok, count, broken_line, reason)."""
    _exists, receipts, broken, reason, total = load_ledger(path)
    if broken is not None:
        return False, total, broken, reason
    return True, len(receipts), None, None


def hash_file(path):
    """(sha256, byte count) of a file, streamed: a large payload is never held in memory (W5-07)."""
    digest, count = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        while chunk := fh.read(READ_CHUNK):
            digest.update(chunk)
            count += len(chunk)
    return digest.hexdigest(), count


def cmd_write(args):
    path, source = resolve_ledger(args.ledger)
    payload_sha = args.payload_sha256
    nbytes = args.bytes
    if args.payload_file:
        try:
            payload_sha, size = hash_file(args.payload_file)
        except OSError as err:
            _print(f"egress: payload file unreadable: {err}", file=sys.stderr)
            return EXIT_USAGE
        if nbytes is None:
            nbytes = size
    record = write_receipt(
        path, args.sink, args.host, args.payload_class, args.consent,
        nbytes=nbytes or 0, payload_sha256=payload_sha, ts=args.ts,
    )
    if note := _routing_note(path, source):
        _print(note, file=sys.stderr)
    _print(record["id"])
    return EXIT_OK


def _anchored_value(raw):
    """The comparable form of an anchored digest: the empty chain's head is
    the empty string, and `(empty)` (what `head` prints for it) means the
    same value — the two commands must round-trip."""
    want = (raw or "").strip().lower()
    return "" if want == "(empty)" else want


def _tamper(path, broken, reason, count):
    _print(f"egress: TAMPER at {path}:{broken} — {reason} ({count} line(s) read)", file=sys.stderr)
    return EXIT_FAIL_CLOSED


def _anchors_fail(args, path, exists, receipts):
    """EXIT_FAIL_CLOSED, said, when an anchor `args` names (--expect-ancestor, --expect-head) does
    not match the chain; None when every requested anchor holds (or none was requested). One check
    for every command that answers from the chain: `verify` and `grants` (re-attack of 2d254d0f,
    W5-04: `grants` took no anchor, so a consent rewritten since the last close printed with rc 0
    while `verify --expect-ancestor` said TAMPER)."""
    head = sha256_hex(receipts[-1][1]) if receipts else ""
    shown = head or "(empty)"
    # A receipt is named by its line's digest (what `head` printed) or by its id (what `write`
    # printed): both bind every byte of that one line, and through `prev` every line before it.
    known = {sha256_hex(raw) for _no, raw, _rec in receipts} | {rec["id"] for _no, _raw, rec in receipts}
    # Both anchors may be requested together; each requested check runs —
    # returning after the ancestor leg would silently skip an exact-head
    # check the caller asked for (PR #567 review, P2).
    ancestors = getattr(args, "expect_ancestor", None)
    if ancestors is not None:
        for want in (_anchored_value(a) for a in ancestors):
            if want and want not in known:
                gone = ("there is no ledger file at all" if not exists
                        else "a rewritten or truncated ledger loses the anchored line")
                _print(f"egress: TAMPER at {path} — the anchored receipt {want} is not in this chain "
                      f"({gone}). Appends since the anchor are fine; this is what an anchor kept off "
                      "the writer catches (#312)", file=sys.stderr)
                return EXIT_FAIL_CLOSED
    expected = getattr(args, "expect_head", None)
    if expected is not None:
        want = _anchored_value(expected)
        last = {head, receipts[-1][2]["id"]} if receipts else {""}
        if want not in last:
            _print(f"egress: TAMPER at {path} — the chain is internally intact, but its head is "
                  f"{shown}, not the anchored {want or '(empty)'}. A ledger rewritten from scratch "
                  "chains perfectly to its own new genesis, so recomputing the chain can never "
                  "catch that; only a head kept where the writer cannot reach it can (#312)",
                  file=sys.stderr)
            return EXIT_FAIL_CLOSED
    return None


UNANCHORED = ("UNANCHORED: edits are caught, a rewrite is not — anchor this head and each id `write` "
              "printed off the writer, and pass them back as --expect-ancestor, or --expect-head for a "
              "sealed ledger")


def cmd_verify(args):
    path, source = resolve_ledger(args.ledger)
    exists, receipts, broken, reason, total = load_ledger(path)
    if broken is not None:
        return _tamper(path, broken, reason, total)
    count = len(receipts)
    head = sha256_hex(receipts[-1][1]) if receipts else ""
    shown = head or "(empty)"
    where = f"{path} ({source})" if exists else f"{path} ({source}) — no ledger file there"
    failed = _anchors_fail(args, path, exists, receipts)
    if failed is not None:
        return failed
    ancestors = getattr(args, "expect_ancestor", None)
    expected = getattr(args, "expect_head", None)
    # No receipts is not a clean bill (W5-03): a close whose receipts were routed elsewhere, or
    # never written, finds none here. It passes only when the caller says none were expected:
    # --allow-empty, or a sealed empty head (--expect-head "(empty)"). The result line goes to
    # stdout as every verify result does; the failure and what to do about it go to stderr.
    sealed_empty = expected is not None and _anchored_value(expected) == ""
    if count == 0 and not sealed_empty:
        if not getattr(args, "allow_empty", False):
            _print(f"egress: NO RECEIPTS, 0 receipt(s) in {where} — nothing was verified")
            _print(f"egress: NO RECEIPTS in {where} — a close that expects receipts must find them here; if "
                   "this run sent nothing, say so with --allow-empty", file=sys.stderr)
            return EXIT_NO_RECEIPTS
        _print(f"egress: NO RECEIPTS, 0 receipt(s) in {where} — none expected (--allow-empty)")
        return EXIT_OK
    if expected is not None:
        _print(f"egress: chain intact and anchored, {count} receipt(s) in {where} — head {shown}")
        return EXIT_OK
    if ancestors is not None:
        _print(f"egress: chain intact, anchored receipt(s) present, {count} receipt(s) "
              f"in {where} — head {shown}")
        return EXIT_OK
    _print(f"egress: chain intact, {count} receipt(s) in {where} — head {shown} ({UNANCHORED})")
    return EXIT_OK


def cmd_head(args):
    """Print the chain head for anchoring off the writer (#561).

    Verifies first: a head taken from a broken chain would anchor the
    tampering. Run close records this value (conductor-close.md) and the
    next close passes the previous one to verify --expect-ancestor.
    """
    path, _source = resolve_ledger(args.ledger)
    _exists, receipts, broken, reason, total = load_ledger(path)
    if broken is not None:
        return _tamper(path, broken, reason, total)
    _print(sha256_hex(receipts[-1][1]) if receipts else "(empty)")
    return EXIT_OK


def cmd_grants(args):
    """The consents a VERIFIED chain records: a ledger `verify` calls tampered answers nothing about
    what the fleet is allowed to do (W5-04). The anchors are `verify`'s, checked the same way: a
    chain checked only against itself is said to be UNANCHORED (on stdout, or on stderr beside
    --json), since every receipt written since the last anchor can be rewritten consistently."""
    path, _source = resolve_ledger(args.ledger)
    exists, receipts, broken, reason, total = load_ledger(path)
    if broken is not None:
        return _tamper(path, broken, reason, total)
    failed = _anchors_fail(args, path, exists, receipts)
    if failed is not None:
        return failed
    anchored = getattr(args, "expect_ancestor", None) is not None or getattr(args, "expect_head", None) is not None
    grants = {}
    for _lineno, _raw, record in receipts:
        key = record["consent"]
        entry = grants.setdefault(key, {"consent": key, "uses": 0, "sinks": set(), "hosts": set()})
        entry["uses"] += 1
        entry["sinks"].add(record["sink"])
        entry["hosts"].add(record["host"])
    rows = [
        {"consent": g["consent"], "uses": g["uses"],
         "sinks": sorted(s for s in g["sinks"] if s),
         "hosts": sorted(h for h in g["hosts"] if h)}
        for g in sorted(grants.values(), key=lambda g: g["consent"])
    ]
    if args.json:
        print(json.dumps(rows, indent=2))  # JSON escapes every control and non-ASCII character itself
    else:
        if not rows:
            _print(f"egress: no consents recorded in {path}")
        for row in rows:
            _print(f"{row['consent']}  uses={row['uses']}  sinks={','.join(row['sinks'])}  "
                  f"hosts={','.join(row['hosts'])}")
    if not anchored:
        _print(f"egress: these consents come from a chain checked only against itself ({UNANCHORED})",
               file=sys.stderr if args.json else sys.stdout)
    return EXIT_OK


def _ts_arg(value):
    try:
        return valid_ts(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err)) from err


def build_parser():
    p = argparse.ArgumentParser(
        prog="egress.py",
        description="Content-free hash-chained receipts for off-repo sends.",
        epilog="exit 0 ok / 2 usage / 3 fail-closed (receipt unwritable, or chain tampered) / 4 verify found "
               "no receipts (pass --allow-empty when none were sent)",
    )
    p.add_argument("--ledger", default=None,
                   help=f"ledger path (default ${PRIMARY_LEDGER_ENV}, ${LEDGER_ENV}, or "
                        f"<repository root>/{DEFAULT_LEDGER})")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("write", help="append one receipt BEFORE the send; prints its id, an anchor")
    w.add_argument("--sink", required=True, help="which fleet component is sending, e.g. pr-open")
    w.add_argument("--host", required=True, help="destination host[:port]")
    w.add_argument("--payload-class", required=True, dest="payload_class",
                   help="content-free description of the payload kind, e.g. pr-body")
    w.add_argument("--consent", required=True, help="the standing grant that authorizes this send")
    w.add_argument("--bytes", type=int, default=None, help="exact byte count (default 0, or the payload file's size)")
    w.add_argument("--payload-file", default=None, help="file whose exact bytes are being sent; hashed, never stored")
    w.add_argument("--payload-sha256", default=None, dest="payload_sha256",
                   help="sha256 of the bytes, when a subprocess owns them")
    w.add_argument("--ts", default=None, type=_ts_arg,
                   help="ISO-8601 instant with offset, e.g. 2026-01-02T03:04:05Z (default: now, UTC)")

    v = sub.add_parser("verify", help="recompute the hash chain")
    v.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    _anchor_arguments(v)
    v.add_argument("--allow-empty", action="store_true", dest="allow_empty",
                   help="this run sent nothing: no ledger, or an empty one, passes. Without it, "
                        "no receipts exits 4, never 0 (W5-03); an anchor naming a receipt still fails")
    v.add_argument("--require-receipts", action="store_true", dest="require_receipts",
                   help="the default since no receipts exits 4; kept so a close written for the "
                        "opt-in form still runs")

    sub.add_parser("head", help="verify, then print the chain head to anchor off the writer")

    g = sub.add_parser("grants", help="verify (with verify's anchors), then list the standing consents "
                                      "the ledger records")
    g.add_argument("--json", action="store_true", help="emit JSON")
    _anchor_arguments(g)
    return p


def _anchor_arguments(p):
    p.add_argument("--expect-head", default=None, dest="expect_head", metavar="SHA256",
                   help="the head digest (or last receipt id) last recorded OFF this writer; the "
                        "ledger must END exactly there. Without any anchor the chain is only checked "
                        "against itself, which a wholesale rewrite satisfies (#312)")
    p.add_argument("--expect-ancestor", default=None, action="append", dest="expect_ancestor",
                   metavar="SHA256",
                   help="a head digest recorded OFF this writer at an earlier close, or a receipt id "
                        "`write` printed; that line must still be IN the chain, byte for byte. "
                        "Repeatable. Receipts appended since are expected — this is the "
                        "close-to-close form (#561)")


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"write": cmd_write, "verify": cmd_verify, "head": cmd_head,
                "grants": cmd_grants}
    try:
        return handlers[args.command](args)
    except EgressError as err:
        _print(f"egress: EGRESS_RECEIPT_FAILED: {err}", file=sys.stderr)
        return EXIT_FAIL_CLOSED


if __name__ == "__main__":
    sys.exit(main())
