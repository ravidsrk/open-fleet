#!/usr/bin/env python3
"""Content-free, hash-chained receipts for everything the fleet sends off-repo.

The run-close integrity inventory hashes what the fleet PRODUCED. Nothing
records what it SENT. This ledger is the second half: one line per off-repo
write the fleet performs -- opening a PR, posting a comment, closing an issue,
triggering a deploy, creating a schedule -- appended BEFORE the send.

Status, stated first because it bounds what this is worth today: doctrine now names it —
merge-serialization.md requires every coordinator off-repo write to be preceded by
``egress.py write … &&`` (#368) — but no automated sink calls it yet, so the receipts are
still not being written by anything but a coordinator that follows the policy by hand. Read
every sentence below as what it records once called, not as a guarantee a daemon enforces.

Threat model, stated because it bounds what this is worth even then: the
ledger is forensic observability, not an exfiltration control. It records ATTEMPTED
egress so an accident is auditable afterwards. Anything with a shell can send
without a receipt; the point is that the fleet's own sinks cannot do so
silently.

Record (one JSON object per line, ``.orca/egress.jsonl``, mode 0600)::

    {"id", "ts", "sink", "host", "payload_class", "bytes",
     "payload_sha256", "consent", "prev"}

* **Content-free.** Never the payload text: a sha256 of the exact bytes sent
  and a byte count, and a ``payload_class`` that describes the KIND of thing
  sent ("pr-body", "issue-comment"). ``payload_sha256`` is null when a
  subprocess owns the bytes and the fleet never saw them.
* **Tamper-evident against EDITS, and only that without an anchor.** ``prev``
  is the sha256 of the previous raw line (``""`` on line 1), so any edit to an
  earlier line breaks every later one. ``id`` is the sha256 of this record's
  own fields including ``prev`` -- it names the line and its position in the
  chain at once. What a self-check cannot catch is a ledger deleted and
  rewritten from scratch: the new chain starts at its own genesis and every
  link is correct, so ``verify`` reports it intact (#312). The chain proves
  continuity with *a* genesis, never with *the* one. So ``verify`` prints the
  head digest and takes ``--expect-head``: record that head somewhere the
  writer cannot reach -- a coordinator, CI, the run's own evidence manifest --
  and hand it back, and a replaced history is caught. Unanchored, the output
  says so rather than reading as a clean bill.
* **Fail-closed on write.** A sink that cannot write its receipt must not
  send. ``write`` exits 3 in that case, so the caller's ``&&`` stops.
* **Consent is a field, not a vibe.** Every receipt names the standing grant
  that authorizes the send; ``grants`` lists them so a human can see what the
  fleet believes it is allowed to do.

Subcommands
    write    append one receipt, print its id
    verify   recompute the whole chain
    grants   list the distinct consents, with sink/host and use counts

Exit codes
    0  ok (``verify``: the chain is intact)
    2  usage -- a missing or malformed argument
    3  fail-closed: the receipt could not be written, or ``verify`` found a
       broken/unparseable line. Never treat a 3 as permission to send.

How to wire
    Every off-repo write the coordinator itself performs is preceded by
    ``egress.py write ... && <the send>`` -- the ``&&`` is the fail-closed
    coupling, since exit 3 stops the send. ``--payload-file`` hashes the exact
    bytes about to go out (a PR body written to a file first), so a later
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
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAIL_CLOSED = 3

DEFAULT_LEDGER = ".orca/egress.jsonl"
PRIMARY_LEDGER_ENV = "OPEN_FLEET_EGRESS_LEDGER"
LEDGER_ENV = "ORCA_EGRESS_LEDGER"
# Field order is fixed so `id` is reproducible byte-for-byte on re-verification.
FIELDS = ("ts", "sink", "host", "payload_class", "bytes", "payload_sha256", "consent", "prev")
MAX_FIELD_BYTES = 512


class EgressError(Exception):
    """Fail-closed condition: the receipt could not be written."""


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def ledger_path(explicit=None):
    if explicit:
        return Path(explicit)
    for var in (PRIMARY_LEDGER_ENV, LEDGER_ENV):
        env = os.environ.get(var)
        if env:
            return Path(env)
    return Path(DEFAULT_LEDGER)


# A ts is ISO-8601 to the second (optional fraction) with an explicit UTC offset, the shape
# `now` writes. It was the one free-text field never checked, and `record_id` joins `k=v` with
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


def record_id(record):
    """sha256 over the record's fields in fixed order, chain position included.

    The `k=v` lines are joined with newlines, so the encoding is unambiguous only while no
    value carries one: write refuses such fields and verify fails any record that has one.
    """
    payload = "\n".join(f"{k}={json_scalar(record.get(k))}" for k in FIELDS)
    return sha256_hex(payload)


def json_scalar(value):
    return "" if value is None else str(value)


def last_raw_line(path):
    try:
        with path.open("rb") as fh:
            lines = [ln for ln in fh.read().split(b"\n") if ln]
    except FileNotFoundError:
        return None
    except OSError as err:
        raise EgressError(f"{path} is unreadable: {err}") from err
    if not lines:
        return None
    return lines[-1].decode("utf-8", errors="replace")


def require_field(value, name):
    if not value or not str(value).strip():
        raise EgressError(f"receipt requires a non-empty {name}")
    text = str(value)
    if len(text.encode("utf-8")) > MAX_FIELD_BYTES:
        raise EgressError(f"receipt {name} exceeds {MAX_FIELD_BYTES} bytes")
    if "\n" in text or "\r" in text:
        raise EgressError(f"receipt {name} may not contain a newline (one receipt, one line)")
    return text


def write_receipt(path, sink, host, payload_class, consent, nbytes=0, payload_sha256=None, ts=None):
    """Append one chained receipt. Raises EgressError on any failure (fail closed)."""
    if ts is not None:
        try:
            valid_ts(ts)
        except ValueError as err:
            raise EgressError(str(err)) from err
    record = {
        "ts": ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sink": require_field(sink, "sink"),
        "host": require_field(host, "host"),
        "payload_class": require_field(payload_class, "payload_class"),
        "bytes": int(nbytes),
        "payload_sha256": payload_sha256,
        "consent": require_field(consent, "consent"),
    }
    if record["bytes"] < 0:
        raise EgressError("receipt bytes must be a non-negative integer")
    if payload_sha256 is not None and not _is_sha256(payload_sha256):
        raise EgressError("payload_sha256 must be 64 lowercase hex characters or absent")
    try:
        path.parent.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8",
                  opener=lambda name, flags: os.open(name, flags, stat.S_IRUSR | stat.S_IWUSR)) as fh:
            # All cooperating writers hold this inode's lock through the flush;
            # the next tail reader must see the complete preceding receipt.
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            previous = last_raw_line(path)
            record["prev"] = "" if previous is None else sha256_hex(previous)
            record["id"] = record_id(record)
            line = json.dumps({"id": record["id"], **{k: record[k] for k in FIELDS}},
                              separators=(",", ":"), sort_keys=False)
            fh.write(line + "\n")
            fh.flush()
    except EgressError:
        raise
    except OSError as err:
        raise EgressError(f"receipt could not be written to {path}: {err}") from err
    return record


def _is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def read_ledger(path):
    """[(lineno, raw, record-or-None)]. A missing ledger is an empty chain."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except UnicodeDecodeError as err:
        # A ValueError, not an OSError — without this arm the forensic reader tracebacks
        # (exit 1) instead of failing closed on-contract (exit 3) (#382).
        raise EgressError(f"{path} is not valid UTF-8: {err}") from err
    except OSError as err:
        raise EgressError(f"{path} is unreadable: {err}") from err
    out = []
    for i, raw in enumerate([ln for ln in text.split("\n") if ln], 1):
        try:
            parsed = json.loads(raw)
            record = parsed if isinstance(parsed, dict) else None
        except ValueError:
            record = None
        out.append((i, raw, record))
    return out


def head_digest(path):
    """sha256 of the ledger's LAST raw line — the value to anchor off the writer (#312).

    Empty string for an empty chain. This is the only thing a wholesale rewrite cannot reproduce:
    the chain it writes is internally perfect, starting at its own genesis with every link correct,
    but it is a DIFFERENT chain and so has a different head."""
    lines = read_ledger(path)
    return sha256_hex(lines[-1][1]) if lines else ""


def verify_ledger(path):
    """Recompute the chain. Returns (ok, count, broken_line, reason)."""
    lines = read_ledger(path)
    previous_raw = None
    for lineno, raw, record in lines:
        if record is None or not isinstance(record.get("prev"), str):
            return False, len(lines), lineno, "unparseable line or missing prev"
        expected_prev = "" if previous_raw is None else sha256_hex(previous_raw)
        if record["prev"] != expected_prev:
            return False, len(lines), lineno, "prev does not match the previous raw line"
        if any(isinstance(record.get(k), str) and ("\n" in record[k] or "\r" in record[k])
               for k in FIELDS):
            return False, len(lines), lineno, "a field carries a line break (ambiguous id encoding)"
        if record.get("id") != record_id(record):
            return False, len(lines), lineno, "id does not match the record's own fields"
        previous_raw = raw
    return True, len(lines), None, None


def cmd_write(args):
    path = ledger_path(args.ledger)
    payload_sha = args.payload_sha256
    nbytes = args.bytes
    if args.payload_file:
        try:
            data = Path(args.payload_file).read_bytes()
        except OSError as err:
            print(f"egress: payload file unreadable: {err}", file=sys.stderr)
            return EXIT_USAGE
        payload_sha = sha256_hex(data)
        if nbytes is None:
            nbytes = len(data)
    record = write_receipt(
        path, args.sink, args.host, args.payload_class, args.consent,
        nbytes=nbytes or 0, payload_sha256=payload_sha, ts=args.ts,
    )
    print(record["id"])
    return EXIT_OK


def _anchored_value(raw):
    """The comparable form of an anchored digest: the empty chain's head is
    the empty string, and `(empty)` (what `head` prints for it) means the
    same value — the two commands must round-trip."""
    want = (raw or "").strip().lower()
    return "" if want == "(empty)" else want


def cmd_verify(args):
    path = ledger_path(args.ledger)
    ok, count, broken, reason = verify_ledger(path)
    if not ok:
        print(f"egress: TAMPER at {path}:{broken} — {reason} ({count} line(s) read)", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    head = head_digest(path) or ""
    shown = head or "(empty)"
    # Both anchors may be requested together; each requested check runs —
    # returning after the ancestor leg would silently skip an exact-head
    # check the caller asked for (PR #567 review, P2).
    ancestor = getattr(args, "expect_ancestor", None)
    anchored = False
    if ancestor is not None:
        want = _anchored_value(ancestor)
        if want:
            digests = {sha256_hex(raw.encode("utf-8"))
                       for _no, raw, _rec in read_ledger(path)}
            if want not in digests:
                print(f"egress: TAMPER at {path} — the anchored head {want} is not in "
                      "this chain. Appends since the anchor are fine; a rewritten or "
                      "truncated ledger loses the anchored line, and that is what "
                      "this caught (#312)", file=sys.stderr)
                return EXIT_FAIL_CLOSED
        anchored = True
    expected = getattr(args, "expect_head", None)
    if expected is not None:
        want = _anchored_value(expected)
        if want != head:
            print(f"egress: TAMPER at {path} — the chain is internally intact, but its head is "
                  f"{shown}, not the anchored {want or '(empty)'}. A ledger rewritten from scratch "
                  "chains perfectly to its own new genesis, so recomputing the chain can never "
                  "catch that; only a head kept where the writer cannot reach it can (#312)",
                  file=sys.stderr)
            return EXIT_FAIL_CLOSED
        print(f"egress: chain intact and anchored, {count} receipt(s) in {path} — head {shown}")
        return EXIT_OK
    if anchored:
        print(f"egress: chain intact, anchored head present, {count} receipt(s) "
              f"in {path} — head {shown}")
        return EXIT_OK
    print(f"egress: chain intact, {count} receipt(s) in {path} — head {shown} "
          "(UNANCHORED: edits are caught, a wholesale rewrite is not — anchor this head off the "
          "writer and pass it back as --expect-ancestor, or --expect-head for a sealed ledger)")
    return EXIT_OK


def cmd_head(args):
    """Print the chain head for anchoring off the writer (#561).

    Verifies first: a head taken from a broken chain would anchor the
    tampering. Run close records this value (conductor-close.md) and the
    next close passes the previous one to verify --expect-ancestor.
    """
    path = ledger_path(args.ledger)
    ok, count, broken, reason = verify_ledger(path)
    if not ok:
        print(f"egress: TAMPER at {path}:{broken} — {reason} ({count} line(s) read)",
              file=sys.stderr)
        return EXIT_FAIL_CLOSED
    print(head_digest(path) or "(empty)")
    return EXIT_OK


def cmd_grants(args):
    path = ledger_path(args.ledger)
    grants = {}
    for _lineno, _raw, record in read_ledger(path):
        if not record:
            continue
        key = record.get("consent", "(none)")
        entry = grants.setdefault(key, {"consent": key, "uses": 0, "sinks": set(), "hosts": set()})
        entry["uses"] += 1
        entry["sinks"].add(record.get("sink", ""))
        entry["hosts"].add(record.get("host", ""))
    rows = [
        {"consent": g["consent"], "uses": g["uses"],
         "sinks": sorted(s for s in g["sinks"] if s),
         "hosts": sorted(h for h in g["hosts"] if h)}
        for g in sorted(grants.values(), key=lambda g: g["consent"])
    ]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print(f"egress: no consents recorded in {path}")
        for row in rows:
            print(f"{row['consent']}  uses={row['uses']}  sinks={','.join(row['sinks'])}  "
                  f"hosts={','.join(row['hosts'])}")
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
        epilog="exit 0 ok / 2 usage / 3 fail-closed (receipt unwritable, or chain tampered)",
    )
    p.add_argument("--ledger", default=None,
                   help=f"ledger path (default ${LEDGER_ENV} or {DEFAULT_LEDGER})")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("write", help="append one receipt BEFORE the send")
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
    v.add_argument("--expect-head", default=None, dest="expect_head", metavar="SHA256",
                   help="the head digest last recorded OFF this writer; the ledger must END "
                        "exactly there. Without any anchor the chain is only checked against "
                        "itself, which a wholesale rewrite satisfies (#312)")
    v.add_argument("--expect-ancestor", default=None, dest="expect_ancestor", metavar="SHA256",
                   help="a head digest recorded OFF this writer at an earlier close; receipts "
                        "appended since are expected — the anchored line must still be IN "
                        "the chain. This is the close-to-close form (#561)")

    sub.add_parser("head", help="verify, then print the chain head to anchor off the writer")

    g = sub.add_parser("grants", help="list the standing consents the ledger records")
    g.add_argument("--json", action="store_true", help="emit JSON")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"write": cmd_write, "verify": cmd_verify, "head": cmd_head,
                "grants": cmd_grants}
    try:
        return handlers[args.command](args)
    except EgressError as err:
        print(f"egress: EGRESS_RECEIPT_FAILED: {err}", file=sys.stderr)
        return EXIT_FAIL_CLOSED


if __name__ == "__main__":
    sys.exit(main())
