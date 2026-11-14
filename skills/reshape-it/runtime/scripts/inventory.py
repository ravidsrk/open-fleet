#!/usr/bin/env python3
"""Regenerate and re-check the integrity inventory embedded in a report.

A run report closes with an inventory of the artifacts it produced and their
sha256. Written by hand it is a claim; re-derived it is a check. This script is
both halves: ``write`` regenerates the block from the files on disk, ``check``
re-hashes every listed path and reports the drift.

Two block shapes are recognised, because both are already in use. Under a
heading matching ``## ... integrity inventory (sha256)`` (any depth, any leading
words, case-insensitive):

* a fenced block of ``<sha256>  <path>`` lines -- the ``sha256sum`` format; and
* a markdown table of ``| `path` | `hash` |`` rows, with a ``| --- |``
  separator row skipped.

Paths resolve against the repo root first, then against the report's own
directory -- a run report lists repo-relative paths, a per-directory README
lists its own siblings, and both are correct.

An inventory that names a path which no longer exists is NOT a mismatch. A
report is a dated snapshot: it may pin artifacts from a slice tip that has since
moved, or files that were deliberately retired. Those are reported as MISSING
and do not fail ``check``; a path that exists and hashes differently does.

Exit codes
    0  every path that exists matches its recorded hash
    1  at least one existing path hashes differently (``check``), or a path to
       be written does not exist (``write``)
    2  could not run -- no inventory block found, an unreadable report, or
       (``check``) not one listed path exists, so nothing was actually verified.
       A verification that examined nothing must not report success.

How to wire
    ``write`` runs at run close, after the last artifact is final: the block it
    emits is the thing a reader can re-derive. ``check`` runs in the same gate
    that reads the report -- the inventory is what makes a manifest's SHA pins
    meaningful, since a pin nobody re-computes is a comment. Exit 2 is the one
    that matters most: an inventory whose paths have all moved verified nothing,
    and must park rather than pass. Re-derive a historical report's hashes at
    the commit it names, not at HEAD.

    Example: ``inventory.py check docs/runs/2026-08-28-ship-it-self-run.md``

Signing (#386). An inventory a worker can write is a claim a worker can type.
``sign --key <seed>`` signs the document's ENTRY SET — every block's
``(path, sha256)`` pairs, sorted, re-derived from disk first — with the
coordinator's Ed25519 key (dispatch-sign.py's gen-key files, the same envelope
``{record, sig_b64}`` the dispatch record and the verifier transcript use). The
envelope is one detached line inside the inventory block, an HTML comment the
parser ignores and a renderer hides::

    <!-- inventory-signature {"record": {"entries": 2, "inventory_sha256": "…"}, "sig_b64": "…"} -->

``check --pubkey <path>`` then requires it: a missing envelope is refused, a
tampered entry (or signature) fails, another key fails. The envelope is only
ever looked for INSIDE the inventory blocks find_blocks() returns: a matching
line anywhere else in the document (prose, an example) is never an envelope and
is refused when the envelope is read, never honoured and never rewritten; two
envelope lines, a non-JSON line or a non-{record, sig_b64} line refuse too, and
a signature that does not decode is a refusal in its own right — validity is an
affirmative verdict from the key, never the absence of a complaint (round-1
G-1). Without ``--pubkey`` ``check`` reads the block exactly as before, and
``write`` without ``--key`` writes exactly as before: neither reads the envelope
for enforcement — what switches enforcement on for a run report is the
committed ``.orca/dispatch-pubkey``, which run_report.py reads where the
transcript rule reads it. Stdlib only, offline: nothing here reaches a network.

Retention receipts (#608). When the coordinator uploads a signed inventory's digest to a
transparency log (optional, out of band, never a gate), ``receipt --key <seed>`` records
the result as a v1 RECEIPT: the same ``{record, sig_b64}`` envelope, its record exactly
``RECEIPT_FIELDS`` — ``schema`` (``RECEIPT_SCHEMA``), ``unit`` and ``source_revision``
(the graded manifest's ``unit`` and ``head_sha``), ``inventory`` (the repo-relative
document carrying the signed inventory), ``inventory_sha256`` (that inventory's signed
digest), ``log_index`` and ``entry_uuid`` (what the log returned), and ``signer``
(``ed25519:`` + sha256 of the signing public key) — signed over dispatch-sign.py's
canonical form of those fields. verify.py checks it OFFLINE (``--retention-pubkey``)
through ``parse_receipt``, ``verify_receipt`` and ``bind_receipt``, against a key the
verifier is handed and never one the receipt carries. A receipt proves that the
configured key bound this log entry's identifiers to these inventory bytes; it does not
prove that the log entry exists, that anything is retained, or any legal outcome.
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
import base64
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path


def _load_gitexec():
    """gitexec.py, the sibling holding the one git resolution + hardened-env rule."""
    spec = importlib.util.spec_from_file_location(
        "gitexec", Path(__file__).resolve().parent / "gitexec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load_gitexec()

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_CANNOT_RUN = 2

HEADING = re.compile(r"^\s{0,3}#{1,6}\s+.*\bintegrity inventory\s*\(sha256\)", re.IGNORECASE)
NEXT_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+")
FENCE = re.compile(r"^\s*(```+|~~~+)")
SHA_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+(\S.*)$")
TABLE_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
# The detached signature envelope: one HTML-comment line inside an inventory block. Neither
# SHA_LINE nor TABLE_ROW can match it, so every pre-signature parser reads past it unchanged.
SIGNATURE_TAG = "inventory-signature"
SIGNATURE_LINE = re.compile(r"^\s*<!--\s*" + SIGNATURE_TAG + r"\s+(\{.*\})\s*-->\s*$")
SIGNED_FIELDS = ("entries", "inventory_sha256")
# The v1 retention receipt (#608). A closed shape: every field is signed, none is optional, and
# nothing else may ride along — a field outside it is refused rather than ignored, so a receipt
# cannot smuggle a key (or anything else) a lenient reader might honour. `schema` is signed too:
# a v2 record cannot pass as v1, and a receipt signature can never be read as another envelope's.
RECEIPT_SCHEMA = "open-fleet/retention-receipt/v1"
RECEIPT_FIELDS = ("schema", "unit", "source_revision", "inventory", "inventory_sha256",
                  "log_index", "entry_uuid", "signer")
RECEIPT_SHAPES = {
    "source_revision": re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),  # a full commit id
    "inventory_sha256": re.compile(r"^[0-9a-f]{64}$"),
    "entry_uuid": re.compile(r"^(?:[0-9a-f]{16})?[0-9a-f]{64}$"),  # Rekor: leaf hash, tree-id prefix optional
    "signer": re.compile(r"^ed25519:[0-9a-f]{64}$"),
}
_HERE = Path(__file__).resolve().parent


class InventoryError(Exception):
    """Could-not-run: no block, unreadable report, nothing verifiable."""


class SignatureRefused(Exception):
    """The envelope does not verify: the wrong entry set, an undecodable signature, or another
    key. Raised, never returned, so no code path can hand a caller a refusal that looks like a
    verdict."""


class ReceiptRefused(Exception):
    """A retention receipt does not bind (#608): the wrong shape, another signer, a signature that
    does not hold, another unit, revision or inventory. Raised for the same reason as
    SignatureRefused — a refusal must never be mistakable for a verdict."""


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_root(start):
    try:
        r = subprocess.run(gitexec.argv("-C", str(start), "rev-parse", "--show-toplevel"),
                           capture_output=True, text=True, timeout=30, env=gitexec.env(),
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return Path(r.stdout.strip())


def find_blocks(lines):
    """[(start, end)] for EVERY inventory block body, exclusive of the heading. Each block runs to
    the next heading of any depth or EOF.

    Every, not the first (#315). Reading only the first left a second block in the same document
    unhashed and uncompared, so a report could carry one inventory a tool checks and another a
    human reads. A document's integrity claim is all of the claims it makes."""
    blocks = []
    for i, line in enumerate(lines):
        if not HEADING.match(line):
            continue
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if NEXT_HEADING.match(lines[j]):
                end = j
                break
        blocks.append((i, end))
    if not blocks:
        raise InventoryError("no '## … integrity inventory (sha256)' heading found")
    return blocks


def parse_entries(lines, start, end):
    """[(lineno, path, recorded_hash, shape)] for one inventory block."""
    entries = []
    for idx in range(start + 1, end):
        line = lines[idx]
        if FENCE.match(line):
            continue  # fence markers bound the block; entries are read anywhere inside it
        m = SHA_LINE.match(line.strip())
        if m:
            entries.append((idx, m.group(2).strip(), m.group(1).lower(), "fenced"))
            continue
        t = TABLE_ROW.match(line)
        if t:
            cells = [c.strip().strip("`").strip() for c in t.group(1).split("|")]
            if len(cells) < 2 or set("".join(cells)) <= set("-: "):
                continue
            path_cell, hash_cell = cells[0], cells[1]
            if SHA256.match(hash_cell):
                entries.append((idx, path_cell, hash_cell.lower(), "table"))
            elif SHA256.match(path_cell):
                entries.append((idx, hash_cell, path_cell.lower(), "table"))
    if not entries:
        raise InventoryError("the inventory block lists no <sha256> <path> entries")
    return entries


def resolve(path_text, report, root):
    """Repo root first, then the report's own directory. Returns a Path or None.

    An entry names a file UNDER one of those two roots: an absolute path or one climbing out
    with `..` resolves to None here — a report must not point the audit at arbitrary local
    files (#382)."""
    p = Path(path_text)
    if p.is_absolute() or ".." in p.parts:
        return None
    candidates = []
    if root is not None:
        candidates.append(root / path_text)
    candidates.append(report.parent / path_text)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def sha256_at(rev, path_text, cwd):
    """sha256 of `path_text` as it was at git revision `rev`, or None if absent.

    A dated report pins artifacts at the tip it closed on; HEAD has moved since.
    Hashing the blob at that revision is what makes the pin re-derivable years
    later, and it is the only form of the check a fabricated report cannot pass:
    the bytes have to have existed at a commit that exists.
    """
    if not rev or rev.startswith("-"):
        return None  # an option is not a revision; it never reaches git's option position (W2-04)
    proc = subprocess.run(
        gitexec.argv("cat-file", "blob", f"{rev}:{path_text}"),
        cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=gitexec.env(),
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        return None
    return hashlib.sha256(proc.stdout).hexdigest()


def rev_exists(rev, cwd):
    """True iff `rev` names a real commit in the repo at `cwd`."""
    if not rev or rev.startswith("-"):
        return False  # an option is not a revision (W2-04)
    return subprocess.run(
        gitexec.argv("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"),
        cwd=str(cwd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=gitexec.env(),
        stdin=subprocess.DEVNULL,
    ).returncode == 0


def load(report_path):
    report = Path(report_path)
    try:
        text = report.read_text(encoding="utf-8")
    except OSError as err:
        raise InventoryError(f"{report_path} is unreadable: {err}") from err
    lines = text.splitlines()
    entries = []
    for start, end in find_blocks(lines):
        entries.extend(parse_entries(lines, start, end))
    return report, lines, entries


def _dispatch_sign():
    """The signer: canonical form, envelope and the vendored Ed25519 — one scheme, loaded only on
    the signing/verifying paths so a bundle that ships inventory.py alone still writes and checks."""
    spec = importlib.util.spec_from_file_location("dispatch_sign", _HERE / "dispatch-sign.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def canonical_entries(entries):
    """The bytes the coordinator signs: the SET of (path, sha256) pairs across every block, sorted,
    no whitespace. Order and block membership are presentation; the claim is the set (#315)."""
    pairs = sorted({(path_text, recorded) for _idx, path_text, recorded, _shape in entries})
    return json.dumps([list(p) for p in pairs], separators=(",", ":")).encode("utf-8")


def inventory_digest(entries):
    """sha256 of canonical_entries — the one value the signature and a log receipt both bind."""
    return hashlib.sha256(canonical_entries(entries)).hexdigest()


def signature_record(entries):
    return {"entries": len({(p, h) for _i, p, h, _s in entries}), "inventory_sha256": inventory_digest(entries)}


def find_signature(lines):
    """(lineno, envelope) for the signature line inside the document's inventory blocks, or
    (None, None). The scan is scoped to exactly the find_blocks ranges: a matching line outside
    every block is not an envelope and is REFUSED as a would-be forgery, not honoured (BOT-1 —
    the parser only reads those ranges, so only those ranges can carry the claim). Two lines is
    a document signing itself twice — refused, since a reader could not know which one binds."""
    blocks = find_blocks(lines)
    found, stray = [], []
    for idx, line in enumerate(lines):
        m = SIGNATURE_LINE.match(line)
        if m and any(start < idx < end for start, end in blocks):
            found.append((idx, m.group(1)))
        elif m:
            stray.append(idx + 1)
    if stray:
        raise InventoryError(f"{SIGNATURE_TAG} line at line {', '.join(map(str, stray))} sits outside "
                             "every inventory block — not an envelope; refused")
    if not found:
        return None, None
    if len(found) > 1:
        raise InventoryError(f"{len(found)} {SIGNATURE_TAG} lines — a document carries one signature")
    idx, raw = found[0]
    try:
        envelope = json.loads(raw)
    except ValueError as err:
        raise InventoryError(f"the {SIGNATURE_TAG} line is not JSON: {err}") from err
    if not (isinstance(envelope, dict) and isinstance(envelope.get("record"), dict)
            and isinstance(envelope.get("sig_b64"), str)):
        raise InventoryError(f"the {SIGNATURE_TAG} line is not a {{record, sig_b64}} envelope")
    return idx, envelope


def read_pubkey(path):
    """32 raw bytes from a hex pubkey file (gen-key's <out>.pub / .orca/dispatch-pubkey)."""
    try:
        pub = bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as err:
        raise InventoryError(f"pubkey {path} is unreadable or not hex: {err}") from err
    if len(pub) != 32:
        raise InventoryError(f"pubkey {path} is not a 32-byte Ed25519 key")
    return pub


def decode_signature(sig_b64):
    """The 64 signature bytes, or SignatureRefused. A decode or length error is a refusal of its
    own — it can only RED, never fall through to the key: a forger who derives the record from
    the document (anyone can) and types anything into sig_b64 must be refused here (round-1 G-1)."""
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (TypeError, ValueError) as err:
        raise SignatureRefused(f"sig_b64 is malformed ({err})") from err
    if len(sig) != 64:
        raise SignatureRefused(f"sig_b64 is malformed (decodes to {len(sig)} bytes, not a 64-byte "
                               "Ed25519 signature)")
    return sig


def verify_signature(envelope, entries, pub):
    """The inventory digest the coordinator signed — an AFFIRMATIVE value the caller compares to
    inventory_digest(entries) — when `envelope` is the coordinator's signature over exactly this
    entry set; SignatureRefused otherwise. Never None, never a string reason: every refusal
    leaves by the exception, so a malformed envelope cannot be mistaken for a verified one.
    Checked in the order that names the cheaper lie first: the record's digest against the
    entries actually present, the signature's decoding, then the signature over that record."""
    ds = _dispatch_sign()
    record = envelope["record"]
    want = signature_record(entries)
    if record.get("inventory_sha256") != want["inventory_sha256"]:
        raise SignatureRefused(
            f"signature record binds inventory digest {str(record.get('inventory_sha256'))[:12]}…, "
            f"but the entries present digest to {want['inventory_sha256'][:12]}… — an entry was "
            "added, dropped or changed after signing")
    sig = decode_signature(envelope["sig_b64"])
    if not ds._load_ed25519().checkvalid(sig, ds.canonical_record(record, SIGNED_FIELDS), pub):
        raise SignatureRefused("signature INVALID for this pubkey — not the coordinator's inventory "
                               "(tampered, forged, or another key)")
    return want["inventory_sha256"]


def signature_line(seed, entries):
    ds = _dispatch_sign()
    env = ds.envelope(seed, signature_record(entries), SIGNED_FIELDS)
    return f"<!-- {SIGNATURE_TAG} {json.dumps(env, separators=(', ', ': '))} -->"


def _place_signature(lines, line):
    """Replace the existing in-block envelope line, or append one at the end of the FIRST block's
    body (the last non-blank line before the next heading) — inside the range find_blocks reads,
    which is the only place find_signature looks. Prose is never touched: a matching line outside
    the blocks makes find_signature refuse before anything is rewritten (BOT-1)."""
    idx, _env = find_signature(lines)
    if idx is not None:
        lines[idx] = line
        return lines
    start, end = find_blocks(lines)[0]
    at = end
    while at > start + 1 and not lines[at - 1].strip():
        at -= 1
    lines.insert(at, line)
    return lines


def signer_id(pub):
    """A signer's identity: ``ed25519:`` + sha256 of its 32 raw public-key bytes. The verifier
    derives the identity it TRUSTS from the key it was handed; a receipt can only name one."""
    return "ed25519:" + hashlib.sha256(pub).hexdigest()


def receipt_payload(record):
    """The bytes a v1 receipt signature covers (#608): dispatch-sign.py's canonical_record over
    RECEIPT_FIELDS — sorted keys, no whitespace — the one canonical form every signed artifact in
    this toolchain uses, so signer and verifier cannot drift apart."""
    return _dispatch_sign().canonical_record(record, RECEIPT_FIELDS)


def receipt_envelope(seed, record):
    """{record, sig_b64} for a v1 receipt record, signed with the coordinator's seed."""
    return _dispatch_sign().envelope(seed, record, RECEIPT_FIELDS)


def parse_receipt(raw):
    """The v1 receipt envelope in `raw` (bytes), or ReceiptRefused — the SHAPE only; no key is
    consulted here. Closed: the envelope is exactly {record, sig_b64} and the record exactly
    RECEIPT_FIELDS, each in its v1 form. A key-like field anywhere is named as what it is: a
    self-declared key, which establishes no trust."""
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise ReceiptRefused(f"not readable JSON ({err})") from err
    if not (isinstance(envelope, dict) and isinstance(envelope.get("record"), dict)):
        raise ReceiptRefused("not a {record, sig_b64} envelope")
    record = envelope["record"]
    for where, present, allowed in (("envelope", envelope, ("record", "sig_b64")),
                                    ("record", record, RECEIPT_FIELDS)):
        extra = sorted(set(present) - set(allowed))
        keyish = [k for k in extra if "key" in k.lower()]
        if keyish:
            raise ReceiptRefused(
                f"the {where} declares {keyish} — a key inside a receipt never establishes trust; "
                "it is verified only against the key the verifier is handed (--retention-pubkey)")
        if extra:
            raise ReceiptRefused(f"the {where} carries {extra}, outside the {RECEIPT_SCHEMA} shape "
                                 "— refused, not ignored")
    missing = [k for k in RECEIPT_FIELDS if k not in record]
    if missing:
        raise ReceiptRefused(f"the record is missing {missing}")
    if not isinstance(envelope.get("sig_b64"), str):
        raise ReceiptRefused("sig_b64 is missing or not a string")
    if record["schema"] != RECEIPT_SCHEMA:
        raise ReceiptRefused(f"schema {record['schema']!r} is not {RECEIPT_SCHEMA!r} — this verifier "
                             "reads v1 receipts only")
    for field in ("unit", "inventory"):
        if not (isinstance(record[field], str) and record[field].strip()):
            raise ReceiptRefused(f"{field} must be a non-empty string, got {record[field]!r}")
    if type(record["log_index"]) is not int or record["log_index"] < 0:
        raise ReceiptRefused(f"log_index must be a non-negative integer, got {record['log_index']!r}")
    for field, shape in RECEIPT_SHAPES.items():
        if not (isinstance(record[field], str) and shape.match(record[field])):
            raise ReceiptRefused(f"{field} {record[field]!r} is not in its v1 form")
    return envelope


def verify_receipt(envelope, pub, unit, source_revision):
    """The receipt's record when it is the configured signer's statement about THIS unit at THIS
    source revision; ReceiptRefused otherwise. `pub` is the verifier's trust material, never the
    receipt's. Ordered so the cheaper lie is named first: identity, signature, then the replays."""
    record = envelope["record"]
    trusted = signer_id(pub)
    if record["signer"] != trusted:
        raise ReceiptRefused(f"it names signer {record['signer']}, but the configured trust key is "
                             f"{trusted} — signed by, or naming, another key (wrong key)")
    try:
        sig = decode_signature(envelope["sig_b64"])
    except SignatureRefused as err:
        raise ReceiptRefused(f"signature mismatch: {err}") from err
    if not _dispatch_sign()._load_ed25519().checkvalid(sig, receipt_payload(record), pub):
        raise ReceiptRefused("signature mismatch: the signature does not verify under the "
                             "configured key over the v1 payload — a field changed after signing "
                             "(tampered), or the signature is not this key's")
    if record["unit"] != unit:
        raise ReceiptRefused(f"it binds unit {record['unit']!r}, not this manifest's {unit!r} — "
                             "another run's receipt (replay)")
    if record["source_revision"] != source_revision:
        raise ReceiptRefused(f"it binds source revision {record['source_revision']}, not this "
                             f"manifest's head_sha {source_revision!r} — a receipt for another "
                             "revision (replay)")
    return record


def bind_receipt(record, lines, pub):
    """(signed digest, entries) when `lines` — the document the receipt names — carry an inventory
    whose own signature verifies under `pub` over exactly its entries, and whose signed digest is
    the receipt's; ReceiptRefused otherwise. The entries are re-derived from the document, so an
    entry edited after signing is refused here, not trusted from the envelope."""
    try:
        entries = [e for start, end in find_blocks(lines) for e in parse_entries(lines, start, end)]
        _idx, envelope = find_signature(lines)
    except InventoryError as err:
        raise ReceiptRefused(f"the inventory it names cannot be read: {err}") from err
    if envelope is None:
        raise ReceiptRefused(f"{record['inventory']} carries no {SIGNATURE_TAG} — a receipt binds a "
                             "SIGNED inventory, and an unsigned one binds nothing")
    signed = envelope["record"].get("inventory_sha256")
    try:
        verify_signature(envelope, entries, pub)
    except SignatureRefused as err:
        raise ReceiptRefused(f"the inventory's own signature does not hold under the configured "
                             f"key: {err}") from err
    if record["inventory_sha256"] != signed:
        raise ReceiptRefused(f"it binds inventory digest {record['inventory_sha256'][:12]}…, but "
                             f"{record['inventory']} is signed over {str(signed)[:12]}… — a receipt "
                             "for another inventory (replay), or a tampered digest")
    return signed, entries


def check_entries(entries, report, root, at=None):
    """(matched, mismatched, missing) for one inventory, in the tree or at a rev."""
    matched, mismatched, missing = [], [], []
    for _idx, path_text, recorded, _shape in entries:
        if at:
            base = root or report.parent
            actual = sha256_at(at, path_text, base)
            if actual is None and root is not None:
                # rev:path resolves against the repo ROOT; the documented report-relative
                # shape (a per-directory README listing its siblings) needs the second
                # spelling or every sibling entry reads MISSING (#382).
                try:
                    rel_dir = report.parent.resolve().relative_to(Path(root).resolve())
                except ValueError:
                    rel_dir = None
                if rel_dir is not None:
                    actual = sha256_at(at, f"{rel_dir.as_posix()}/{path_text}", base)
            if actual is None:
                missing.append(path_text)
                continue
        else:
            resolved = resolve(path_text, report, root)
            if resolved is None:
                missing.append(path_text)
                continue
            try:
                actual = sha256_file(resolved)
            except OSError as err:
                raise InventoryError(f"{path_text} could not be hashed: {err}") from err
        if actual == recorded:
            matched.append(path_text)
        else:
            mismatched.append((path_text, recorded, actual))
    return matched, mismatched, missing


def cmd_check(args):
    report, _lines, entries = load(args.report)
    root = repo_root(report.parent if report.parent.exists() else Path("."))
    at = getattr(args, "at", None)
    if at and not rev_exists(at, root or report.parent):
        raise InventoryError(f"--at {at} is not a commit in this repo")
    matched, mismatched, missing = check_entries(entries, report, root, at)
    if not matched and not mismatched:
        raise InventoryError(
            f"none of the {len(entries)} listed path(s) exist" + (f" at {at}" if at else "")
            + " — nothing was verified; "
            "re-derive the hashes at the commit the report names")
    for path_text, recorded, actual in mismatched:
        print(f"MISMATCH {path_text}\n  recorded {recorded}\n  actual   {actual}", file=sys.stderr)
    where = f"the tree at {at}" if at else "the tree"
    for path_text in missing:
        print(f"MISSING  {path_text} (not present in {where} — not a mismatch)")
    print(f"inventory: {len(matched)} verified, {len(mismatched)} mismatched, "
          f"{len(missing)} missing, in {args.report}" + (f" at {at}" if at else ""))
    pubkey = getattr(args, "pubkey", None)
    if pubkey:
        # Enforcement is ON: the entry set must carry the coordinator's signature. Without
        # --pubkey the envelope is never read — today's path, byte for byte.
        pub = read_pubkey(pubkey)
        _idx, envelope = find_signature(_lines)
        if envelope is None:
            print(f"UNSIGNED inventory: no {SIGNATURE_TAG} line, and a pubkey is configured — "
                  "refused; sign it with `inventory.py sign --key <seed>`", file=sys.stderr)
            return EXIT_MISMATCH
        try:
            signed = verify_signature(envelope, entries, pub)
        except SignatureRefused as why:
            print(f"SIGNATURE {why}", file=sys.stderr)
            return EXIT_MISMATCH
        if signed != inventory_digest(entries):  # verified means the key said so over THIS set
            print(f"SIGNATURE verifier returned {signed!r}, not this inventory's digest — refused",
                  file=sys.stderr)
            return EXIT_MISMATCH
        print(f"inventory: signature verified over {len(entries)} entr"
              f"{'y' if len(entries) == 1 else 'ies'} (digest {signed[:12]}…) against {pubkey}")
    return EXIT_MISMATCH if mismatched else EXIT_OK


def cmd_write(args):
    report, lines, entries = load(args.report)
    root = repo_root(report.parent if report.parent.exists() else Path("."))
    updated, absent = 0, []
    for idx, path_text, recorded, _shape in entries:
        resolved = resolve(path_text, report, root)
        if resolved is None:
            absent.append(path_text)
            continue
        actual = sha256_file(resolved)
        if actual == recorded:
            continue
        # Exactly one 64-hex token per entry line; replace it in place so the
        # surrounding formatting (fence or table cell) survives untouched.
        lines[idx] = re.sub(r"[0-9a-fA-F]{64}", actual, lines[idx], count=1)
        updated += 1
    if absent:
        for path_text in absent:
            print(f"inventory: cannot hash {path_text} — it does not exist", file=sys.stderr)
        return EXIT_MISMATCH
    if args.dry_run:
        print(f"inventory: would update {updated} hash(es) in {args.report}")
        return EXIT_OK
    key = getattr(args, "key", None)
    if key:
        # Sign the entries as just rewritten — each entry line now carries the on-disk hash.
        fresh = [(i, p, re.search(r"[0-9a-fA-F]{64}", lines[i]).group(0).lower(), sh)
                 for i, p, _h, sh in entries]
        lines = _place_signature(lines, signature_line(_read_seed(key), fresh))
    elif updated and _stale_envelope(lines):
        # Never drop evidence silently: the old envelope stays, and `check --pubkey` will refuse
        # it — which is the honest state of an inventory whose set changed after signing.
        print(f"inventory: the {SIGNATURE_TAG} is now STALE ({updated} entr"
              f"{'y' if updated == 1 else 'ies'} changed) — re-sign with `write --key` or `sign`",
              file=sys.stderr)
    try:
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as err:
        raise InventoryError(f"{args.report} could not be written: {err}") from err
    print(f"inventory: updated {updated} hash(es) in {args.report}"
          + (" and re-signed" if key else ""))
    return EXIT_OK


def _stale_envelope(lines):
    """Whether an unsigned `write` just outdated an in-block envelope — advisory only. The path
    with no --key is the pre-#386 write, byte for byte in what it writes and how it exits: it
    never refuses over the envelope, so any refusal find_signature would raise (a stray line, two
    lines, a malformed one) is left for `check --pubkey` / `sign` to name."""
    try:
        return find_signature(lines)[1] is not None
    except InventoryError:
        return False


def _read_seed(key):
    seed, err = _dispatch_sign()._seed(Path(key))
    if err:
        raise InventoryError(err)
    return seed


def cmd_sign(args):
    """Sign the entry set as re-derived from disk. A stale or absent path is not something to
    attest: `sign` refuses (exit 1) where `check` would, and leaves the document unsigned."""
    report, lines, entries = load(args.report)
    root = repo_root(report.parent if report.parent.exists() else Path("."))
    _matched, mismatched, missing = check_entries(entries, report, root)
    for path_text, recorded, actual in mismatched:
        print(f"MISMATCH {path_text}\n  recorded {recorded}\n  actual   {actual}", file=sys.stderr)
    for path_text in missing:
        print(f"MISSING  {path_text} — not on disk, so not attestable", file=sys.stderr)
    if mismatched or missing:
        print("inventory: refusing to sign — run `inventory.py write` first", file=sys.stderr)
        return EXIT_MISMATCH
    lines = _place_signature(lines, signature_line(_read_seed(args.key), entries))
    try:
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as err:
        raise InventoryError(f"{args.report} could not be written: {err}") from err
    print(f"inventory: signed {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
          f"(digest {inventory_digest(entries)[:12]}…) in {args.report}")
    return EXIT_OK


def cmd_receipt(args):
    """Write the v1 retention receipt (#608) for a report whose inventory is SIGNED by this same
    seed and still re-derives from disk — the coordinator's record of an upload it already made.
    Nothing is uploaded or looked up here: --log-index and --entry-uuid are what the log returned.
    The receipt is parsed back before it is written, so the signer never emits a shape the
    verifier would refuse."""
    report, lines, entries = load(args.report)
    root = repo_root(report.parent if report.parent.exists() else Path("."))
    if root is None:
        raise InventoryError(f"{args.report} is not inside a git work tree — a receipt names its "
                             "inventory repo-relative")
    _matched, mismatched, missing = check_entries(entries, report, root)
    for path_text in [p for p, _r, _a in mismatched] + missing:
        print(f"STALE    {path_text} — the inventory no longer re-derives from disk", file=sys.stderr)
    if mismatched or missing:
        print("inventory: refusing to write a receipt — run `inventory.py write` and `sign` first",
              file=sys.stderr)
        return EXIT_MISMATCH
    seed = _read_seed(args.key)
    pub = _dispatch_sign()._load_ed25519().publickey(seed)
    _idx, envelope = find_signature(lines)
    if envelope is None:
        print(f"inventory: refusing to write a receipt — {args.report} carries no {SIGNATURE_TAG}; "
              "a receipt binds a SIGNED inventory (`inventory.py sign --key <seed>`)", file=sys.stderr)
        return EXIT_MISMATCH
    try:
        signed = verify_signature(envelope, entries, pub)
    except SignatureRefused as why:
        print(f"inventory: refusing to write a receipt — the inventory signature does not hold "
              f"under this seed's key: {why}", file=sys.stderr)
        return EXIT_MISMATCH
    try:
        rel = report.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError as err:
        raise InventoryError(f"{args.report} is outside the repository at {root}") from err
    record = {"schema": RECEIPT_SCHEMA, "unit": args.unit, "source_revision": args.source_revision,
              "inventory": rel, "inventory_sha256": signed, "log_index": args.log_index,
              "entry_uuid": args.entry_uuid, "signer": signer_id(pub)}
    receipt = receipt_envelope(seed, record)
    parse_receipt(json.dumps(receipt).encode("utf-8"))
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
        return EXIT_OK
    try:
        Path(args.out).write_text(text, encoding="utf-8")
    except OSError as err:
        raise InventoryError(f"{args.out} could not be written: {err}") from err
    print(f"inventory: wrote the {RECEIPT_SCHEMA} receipt for {rel} (digest {signed[:12]}…, "
          f"log index {args.log_index}) to {args.out}")
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(
        prog="inventory.py",
        description="Regenerate or re-check the sha256 integrity inventory embedded in a report.",
        epilog="exit 0 verified / 1 mismatch / 2 could-not-run (no block, or nothing verifiable)",
    )
    sub = p.add_subparsers(dest="command", required=True)
    w = sub.add_parser("write", help="re-hash every listed path and rewrite the block in place")
    w.add_argument("report", help="markdown report carrying the inventory block")
    w.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    w.add_argument("--key", metavar="SEED",
                   help="re-sign the refreshed entry set with this coordinator seed (gen-key file)")
    c = sub.add_parser("check", help="re-hash every listed path that exists")
    c.add_argument("report", help="markdown report carrying the inventory block")
    c.add_argument(
        "--at",
        metavar="REV",
        help="hash each path as it was at this git revision instead of in the working "
             "tree — the form a dated report's pins stay re-derivable in",
    )
    c.add_argument("--pubkey", metavar="PATH",
                   help="require the coordinator's signature over the entry set, verified against "
                        "this Ed25519 pubkey (.orca/dispatch-pubkey); unsigned or tampered is exit 1")
    sg = sub.add_parser("sign", help="sign the entry set with the coordinator's key (#386)")
    sg.add_argument("report", help="markdown report carrying the inventory block")
    sg.add_argument("--key", required=True, metavar="SEED", help="coordinator seed file from dispatch-sign.py gen-key")
    rc = sub.add_parser("receipt", help="write the v1 retention receipt for a signed inventory (#608)")
    rc.add_argument("report", help="markdown report carrying the SIGNED inventory block")
    rc.add_argument("--key", required=True, metavar="SEED",
                    help="the coordinator seed that signed the inventory (dispatch-sign.py gen-key)")
    rc.add_argument("--unit", required=True, help="the graded manifest's `unit`")
    rc.add_argument("--source-revision", required=True, metavar="SHA",
                    help="the graded manifest's `head_sha` (a full commit id)")
    rc.add_argument("--log-index", required=True, type=int, metavar="N",
                    help="the transparency-log index the upload returned")
    rc.add_argument("--entry-uuid", required=True, metavar="HEX",
                    help="the transparency-log entry UUID the upload returned")
    rc.add_argument("--out", metavar="PATH",
                    help="write the receipt here (the path the manifest's provenance.retention "
                         "names); stdout without it")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"write": cmd_write, "check": cmd_check, "sign": cmd_sign, "receipt": cmd_receipt}
    try:
        return handlers[args.command](args)
    except InventoryError as err:
        print(f"inventory: could not run: {err}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    except ReceiptRefused as err:
        print(f"inventory: receipt not written — {err}", file=sys.stderr)
        return EXIT_CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main())
