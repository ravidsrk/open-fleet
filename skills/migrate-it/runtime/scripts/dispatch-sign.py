#!/usr/bin/env python3
"""dispatch-sign.py — the COORDINATOR's out-of-band signer for #135 (native-hook soundness).

The native Stop/TaskCompleted hook runs IN the graded worker's session, so the worker controls the
env (`ORCA_CONTRACT_DIGEST`, `ORCA_UNIT_CLASS`, …) and could substitute a weaker denominator or
downgrade its class. To make the native path SOUND, the coordinator — which runs OFF the worker
(a separate session, CI, or the human's machine) and holds a private key the worker never sees —
signs the dispatch tuple at dispatch time. The gate (verify.py) verifies that signature against the
repo-pinned PUBLIC key, so an in-session substitution is detected.

    dispatch-sign.py gen-key --out ~/.open-fleet/dispatch-key
        # writes the 32-byte seed to <out> (keep OFF the worker AND out of this repo) and the
        # public key to <out>.pub; commit <out>.pub as .orca/dispatch-pubkey to turn on
        # enforcement (docs/verify-gate.md). gen-key refuses to write a seed inside a git work
        # tree unless the path is git-ignored (or --in-repo-ok is given).

    dispatch-sign.py sign --key ~/.open-fleet/dispatch-key \\
        --manifest-id <unit-id> --contract-digest sha256:… --unit-class mutation [--lighting lit] \\
        [--nc-path src/app.py --nc-command "pytest -k AC_1" --nc-artifact-sha256 <hex>] \\
        [--no-gh] [--lane A|B|0] [--execute-nc]
        # prints the signed envelope JSON the gate consumes via --dispatch-record.
        # The --nc-* inputs are OPTIONAL and cover the negative control itself (#311): signing the
        # class and the contract binds the denominator but leaves the worker choosing its own
        # oracle. Sign them when the coordinator knows the control at dispatch time; when it does
        # not — the usual case, since the fix has not been written yet — the gate binds the same
        # inputs to what base_sha..head_sha actually changes instead (#280).
        # --no-gh / --lane / --execute-nc sign the lane flags the gate takes from argv/env: a
        # run using --no-gh or --lane the record does not sign is refused, and a signed flag the
        # run contradicts (dropping a signed --execute-nc included) is a substitution.

    dispatch-sign.py sign-transcript --key ~/.open-fleet/dispatch-key \\
        --transcript <verdict.json> [--out <transcript.json>]
        # wraps verify.py's VERDICT OBJECT (what `verify.py --transcript-out` writes) in the same
        # {record, sig_b64} envelope, over the same canonical form, with the same key (#281/#386).
        # For the custody model where the seed is OFFLINE: verify.py runs without it, the
        # maintainer signs the verdict afterwards. run_report.py then requires the envelope to
        # verify against the committed .orca/dispatch-pubkey — the same pin that switches the
        # dispatch-record check on. `verify.py --transcript-key` signs in-process instead — on
        # a host that never ran the executed control (verify.py refuses --execute-nc with it;
        # h409 F-6). SIGN ONLY A VERDICT OBJECT YOU PRODUCED: this signer checks shape, not
        # truth — the one content check it makes is that `toolchain.files` hashes THESE
        # scripts, so a verdict from another verifier is refused (h409 O-2.4).

Stdlib-only; the signature scheme is runtime/scripts/ed25519.py (vendored, RFC 8032).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import stat
import shutil
import subprocess

import sys
from pathlib import Path

# h409 hygiene: one git resolution rule across the toolchain —
# resolved once, never a bare PATH lookup per call (reaudit-r2 P3).
GIT = shutil.which("git")


_GIT_ABSENT = "/nonexistent/git"


def _git_cmd(*args):
    """Argv head for every git call: the git resolved once at import — never a bare name that
    would re-resolve against a later PATH (Greptile #498). With no git on PATH the head is a
    fixed nonexistent absolute path, so the failure arrives at EXEC as FileNotFoundError: the
    exact OSError shape the callers' handlers are written for (git-less operation proceeds
    where documented, e.g. dispatch-sign's out-of-repo probe)."""
    return [GIT if GIT is not None else _GIT_ABSENT, *args]

_HERE = Path(__file__).resolve().parent


def _load_ed25519():
    spec = importlib.util.spec_from_file_location("ed25519", _HERE / "ed25519.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The signed fields — the dispatch tuple a worker must not be able to forge. Canonicalized HERE
# only: verify.py loads this file and verifies over canonical_record, so the bytes the signature
# covers cannot drift between signer and gate (2026-10-23 review, P2-2).
#
# The last three are the NEGATIVE-CONTROL inputs (#311). Signing the class and the contract binds
# the denominator and leaves the worker choosing its own oracle: which files get reverted, and what
# command is supposed to go RED. They are OPTIONAL because a coordinator usually cannot know at
# dispatch time which paths a fix will touch — sign them when it can (a targeted mutation unit, a
# re-run of a known defect), and the gate treats a flip as substitution. Unsigned, they fall back
# to being bound against base_sha..head_sha itself (#280), which needs no foreknowledge.
#
# Then the LANE flags (review P2): `no_gh` (the review-waiver lane), `lane` (A|B|0) and
# `execute_nc` (the control must be executed). Each is signed only when set, so a record made
# without them keeps its exact canonical bytes. Bound on the gate: a run using --no-gh or --lane
# the record did not sign is refused, and a signed value the run contradicts is a substitution.
_RECORD_FIELDS = ("manifest_id", "contract_digest", "unit_class", "lighting",
                  "nc_paths", "nc_command", "nc_artifact_sha256",
                  "no_gh", "lane", "execute_nc")
_PROFILE_FIELDS = ("profile", "parent_profile")
PROFILE_RANK = {"ro": 0, "rw": 1, "danger": 2}


# Every source that may bound a child's profile. The CALLER's own sandbox profile is one: the
# launcher exports OPEN_FLEET_SANDBOX_PROFILE into every worker, so a ro worker signing for an
# rw child is refused even when it names no parent or names a wider one (G14).
_PARENT_ENV = ("OPEN_FLEET_PARENT_PROFILE", "ORCA_PARENT_PROFILE",
               "OPEN_FLEET_SANDBOX_PROFILE", "ORCA_SANDBOX_PROFILE")


def effective_parent(*explicit: str | None, env: dict[str, str] | None = None) -> tuple[str | None, str]:
    """(most restrictive parent or None, error). Any unknown value is an error, never skipped."""
    e = env if env is not None else os.environ
    present = [str(p).strip() for p in (*explicit, *(e.get(k) for k in _PARENT_ENV)) if p and str(p).strip()]
    for p in present:
        if p not in PROFILE_RANK:
            return None, f"invalid parent profile {p!r} (expected one of ro, rw, danger)"
    return (min(present, key=PROFILE_RANK.__getitem__) if present else None), ""


def check_profile_narrowing(
    profile: str | None,
    parent_profile: str | None = None,
    env: dict[str, str] | None = None,
    *more_parents: str | None,
) -> tuple[bool, str]:
    """Enforce monotonic privilege narrowing ro < rw < danger (#590).

    The parent is the MOST restrictive of `parent_profile`, `more_parents` and the inherited
    parent/sandbox profile env (G14). Returns (True, "") when valid, or (False, reason) on
    privilege escalation or an invalid profile.
    """
    if profile is not None and profile not in PROFILE_RANK:
        return False, f"invalid profile {profile!r} (expected one of ro, rw, danger)"
    eff_parent, err = effective_parent(parent_profile, *more_parents, env=env)
    if err:
        return False, err
    if profile is not None and eff_parent is not None:
        if PROFILE_RANK[profile] > PROFILE_RANK[eff_parent]:
            return (
                False,
                f"privilege escalation refused: child profile {profile!r} exceeds "
                f"parent profile {eff_parent!r} (monotonic narrowing requires ro <= rw <= danger)",
            )
    return True, ""


# The verifier-transcript fields (#281/#386): verify.py's verdict object, signed so run_report.py
# can require a verdict the worker could not have typed. `manifest_sha256` binds the verdict to the
# manifest BYTES it judged, `args` is the full argument tuple the run used, `fatal`/`notes` are the
# printed verdict, `exit` is the code. All are required — a transcript missing one signs an absence.
TRANSCRIPT_FIELDS = ("unit", "manifest", "manifest_sha256", "args", "fatal", "notes", "exit",
                     "toolchain", "timestamp")

# The files verify.py hashes into `toolchain.files` (verify.py._Transcript.TOOLCHAIN, mirrored
# by run_report.TOOLCHAIN_FILES). sign-transcript re-hashes them against ITS OWN siblings before
# signing (h409 O-2.4): the offline signer is otherwise a rubber stamp over any well-shaped
# object, and after F-6 it is the seed-safe way to sign an executed-control verdict.
TOOLCHAIN_FILES = ("verify.py", "_verify_sig.py", "diff_scope.py", "ed25519.py", "dispatch-sign.py")


def toolchain_mismatch(record: dict) -> str | None:
    """Why `record.toolchain.files` is not the verifier beside this signer, or None when it is."""
    toolchain = record.get("toolchain")
    files = toolchain.get("files") if isinstance(toolchain, dict) else None
    if not isinstance(files, dict):
        return ("verdict object names no toolchain.files — which verifier produced it is unknown; "
                "sign only a verdict object you produced (h409 O-2.4)")
    for name in TOOLCHAIN_FILES:
        signed = files.get(name)
        try:
            here = hashlib.sha256((_HERE / name).read_bytes()).hexdigest()
        except OSError:
            return f"{name} is absent beside this signer, so the verdict's toolchain cannot be re-hashed"
        if not isinstance(signed, str):
            return f"verdict toolchain.files does not name {name} — a partial set binds no verifier"
        if signed != here:
            return (f"verdict toolchain.files pins {name} at {signed[:12]}…, not the file beside this "
                    f"signer ({here[:12]}…) — a different verifier produced it; sign only a verdict "
                    "object you produced (h409 O-2.4)")
    return None


def signed_fields(record: dict, fields=_RECORD_FIELDS) -> tuple:
    """The field list a record is signed over: `fields`, plus _PROFILE_FIELDS for a dispatch
    record that carries a profile (#590). The ONE place that rule lives — canonical_subset and
    envelope both read it here, and verify.py verifies through canonical_record rather than a
    copy, because a copy that dropped the profile rule rejected every profile-signed record as
    forged (2026-10-23 review, P2-2)."""
    if fields is _RECORD_FIELDS and any(record.get(k) is not None for k in _PROFILE_FIELDS):
        return (*_RECORD_FIELDS, *_PROFILE_FIELDS)
    return fields


def canonical_subset(record: dict, fields=_RECORD_FIELDS) -> dict:
    """The signed fields only, with nc_paths reduced to a sorted list of strings.

    A coordinator signs a SET of paths, not a listing order, so ["b","a"] and ["a","b"] must
    produce the same bytes — otherwise a re-ordered manifest reads as a forgery."""
    subset = {k: record[k] for k in signed_fields(record, fields) if record.get(k) is not None}
    if isinstance(subset.get("nc_paths"), list):
        subset["nc_paths"] = sorted(str(x) for x in subset["nc_paths"])
    return subset


def canonical_record(record: dict, fields=_RECORD_FIELDS) -> bytes:
    """Deterministic bytes for signing/verifying: only the signed fields, sorted, no whitespace."""
    return json.dumps(canonical_subset(record, fields), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def canonical_transcript(record: dict) -> bytes:
    """The transcript's canonical bytes — verify.py._canonical_transcript must match byte-for-byte
    (a cross-tool test guards this, as for the dispatch tuple)."""
    return canonical_record(record, TRANSCRIPT_FIELDS)


def _in_unignored_worktree(path: Path) -> bool:
    """True when `path` may be inside a git work tree without ignore coverage.

    A seed written there is one `git add -A` away from being committed (#166), so gen-key refuses
    unless the caller passes --in-repo-ok. `git add -A` can reach the path only if git resolves a
    repository from (a) a `.git` ancestor (dir, or worktree/submodule file) or (b) the ambient
    environment (GIT_DIR / core.worktree) — so we probe both. (a) is a filesystem walk, immune to
    rev-parse's conflation of "not a repo" with real errors; (b) is rev-parse, which honors the
    env. Once git control is established, ignore status comes from `git check-ignore`; git missing
    or an inconclusive result fails CLOSED — an unknown ignore status is not "safe" for a key.
    """
    resolved = path.resolve()
    probe = resolved.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    under_git = False
    ancestor = probe
    while True:
        if (ancestor / ".git").exists():
            under_git = True
            break
        if ancestor == ancestor.parent:
            break
        ancestor = ancestor.parent
    if not under_git:
        # No .git ancestor — the only remaining way `git add` could stage this path is a repo
        # resolved from the environment (GIT_DIR, core.worktree). Ask git itself.
        try:
            top = subprocess.run(_git_cmd("rev-parse", "--show-toplevel"),
                                 cwd=probe, capture_output=True, text=True)
        except OSError:
            return False  # no .git ancestor AND no git binary: nothing can stage the file
        if top.returncode != 0:
            return False  # proven: no work tree claims the path — the out-of-repo layout
        toplevel = Path(top.stdout.strip()).resolve()
        under_git = resolved == toplevel or toplevel in resolved.parents
    if not under_git:
        return False
    try:
        check = subprocess.run(_git_cmd("check-ignore", "-q", "--", str(resolved)),
                               cwd=probe, capture_output=True)
    except OSError:
        return True  # in a work tree but git won't run — cannot prove the path is ignored
    return check.returncode != 0  # 0 = ignored (safe); 1 = not ignored; anything else = unknown


def gen_key(out: Path, in_repo_ok: bool = False) -> int:
    if _in_unignored_worktree(out) and not in_repo_ok:
        print(f"dispatch-sign: REFUSING to write a private seed at {out}", file=sys.stderr)
        print("  the path is (or could not be proven NOT) inside a git work tree and is NOT",
              file=sys.stderr)
        print("  verified git-ignored — one `git add -A` would commit the key and void every",
              file=sys.stderr)
        print("  signed-dispatch guarantee.", file=sys.stderr)
        print("  pick an out-of-repo path (e.g. ~/.open-fleet/dispatch-key), git-ignore it,",
              file=sys.stderr)
        print("  or pass --in-repo-ok if you really mean it.", file=sys.stderr)
        return 2
    ed = _load_ed25519()
    seed = os.urandom(32)
    pub = ed.publickey(seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    # The seed gets its final permissions AT CREATION (os.open mode 0o600), then fchmod on the
    # open fd covers re-generation over a pre-existing permissive file — never create-under-umask
    # then chmod, which leaves the seed world-readable between the two calls (#163).
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(seed.hex() + "\n")
    pub_path = out.with_suffix(out.suffix + ".pub") if out.suffix else Path(str(out) + ".pub")
    pub_path.write_text(pub.hex() + "\n", encoding="utf-8")
    print(f"private seed: {out} (0600 — keep OFF the graded worker)", file=sys.stderr)
    print(f"public key:   {pub_path} (commit as .orca/dispatch-pubkey to enforce)", file=sys.stderr)
    return 0


def _seed(key: Path | None = None):
    """(seed bytes, None) from a gen-key seed file (or OPEN_FLEET_SIGNING_SEED / ORCA_DISPATCH_SIGNING_SEED), or (None, reason).

    h409 F-4: custody is re-asserted at USE, not only at creation. gen-key writes 0600 and refuses
    an unignored in-repo path, but a seed that was chmod'ed, copied, or committed since arrives
    here looking like any other — and a signature by a leaked seed is exactly what the scheme
    exists to exclude. So every signer (sign, sign-transcript, verify.py --transcript-key,
    inventory.py sign/write --key) refuses a seed any group/other bit can read, or one inside a
    git work tree that does not ignore it, and NAMES the custody class of a passing seed on stderr
    so the audit trail says what signed. The check is custody class, never existence: a 0600 seed
    outside any repo, or under an ignored path, keeps working."""
    if key is None:
        env_val = (os.environ.get("OPEN_FLEET_SIGNING_SEED")
                   or os.environ.get("ORCA_DISPATCH_SIGNING_SEED")
                   or "").strip()
        if not env_val:
            return None, "missing --key and neither OPEN_FLEET_SIGNING_SEED nor ORCA_DISPATCH_SIGNING_SEED is set"
        if len(env_val) == 64:
            try:
                seed_bytes = bytes.fromhex(env_val)
                if len(seed_bytes) == 32:
                    print("seed custody: environment seed (OPEN_FLEET_SIGNING_SEED/ORCA_DISPATCH_SIGNING_SEED)", file=sys.stderr)
                    return seed_bytes, None
            except ValueError:
                pass
        key = Path(env_val)
    try:
        mode = stat.S_IMODE(key.stat().st_mode)
    except OSError as exc:
        return None, f"cannot read a hex seed from {key}: {exc}"
    if mode & 0o077:
        return None, (f"seed custody: {key} is mode {mode:04o} — readable beyond its owner, so any "
                      "signature it makes is unattributable; refusing (chmod 0600, or gen-key anew)")
    if _in_unignored_worktree(key):
        return None, (f"seed custody: {key} is inside a git work tree that does not ignore it — "
                      "one `git add -A` (or a past one) makes it public; refusing (move it out of "
                      "the repo or git-ignore it)")
    try:
        seed = bytes.fromhex(key.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        return None, f"cannot read a hex seed from {key}: {exc}"
    if len(seed) != 32:
        return None, "key must be a 32-byte hex seed"
    print(f"seed custody: {key} mode {mode:04o}, outside any unignored work tree", file=sys.stderr)
    return seed, None


def envelope(seed: bytes, record: dict, fields=_RECORD_FIELDS) -> dict:
    """{record, sig_b64}: the signed subset of `record` and an Ed25519 signature over its canonical
    bytes. One envelope shape for the dispatch tuple and the verifier transcript."""
    ed = _load_ed25519()
    sig = ed.signature(canonical_record(record, fields), seed, ed.publickey(seed))
    return {"record": {k: record[k] for k in signed_fields(record, fields) if record.get(k) is not None},
            "sig_b64": base64.b64encode(sig).decode("ascii")}


def sign(key: Path | None, record: dict, parent_profile: str | None = None) -> int:
    ok, reason = check_profile_narrowing(record.get("profile"), parent_profile, None,
                                         record.get("parent_profile"))
    if not ok:
        print(f"dispatch-sign: {reason}", file=sys.stderr)
        return 2
    seed, err = _seed(key)
    if err:
        print(f"dispatch-sign: {err}", file=sys.stderr)
        return 1
    print(json.dumps(envelope(seed, record), indent=2))
    return 0


def verify_dispatch(
    record_ref: str | Path | None = None,
    *,
    pubkey_ref: str | Path | None = None,
    key_ref: str | Path | None = None,
    profile: str | None = None,
    parent_profile: str | None = None,
) -> int:
    """Verify monotonic privilege narrowing and (when envelope + key/pubkey given) Ed25519 signature."""
    env_obj = None
    rec_obj = {}
    if record_ref is not None:
        raw_str = str(record_ref)
        try:
            if raw_str.lstrip().startswith("{"):
                env_obj = json.loads(raw_str)
            else:
                env_obj = json.loads(Path(raw_str).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"dispatch-sign: cannot read dispatch record {record_ref}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(env_obj, dict) or not isinstance(env_obj.get("record"), dict):
            print("dispatch-sign: dispatch record must be an envelope with a 'record' object", file=sys.stderr)
            return 2
        rec_obj = env_obj["record"]

    eff_profile = profile or rec_obj.get("profile")
    # The flag and the SIGNED parent both bound the child; neither can widen the other.
    ok, reason = check_profile_narrowing(eff_profile, parent_profile, None, rec_obj.get("parent_profile"))
    if not ok:
        print(f"dispatch-sign: {reason}", file=sys.stderr)
        return 2

    if env_obj is not None:
        ed = _load_ed25519()
        pub_bytes = None
        if pubkey_ref is not None:
            p_str = str(pubkey_ref).strip()
            try:
                if len(p_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in p_str):
                    pub_bytes = bytes.fromhex(p_str)
                else:
                    pub_bytes = bytes.fromhex(Path(p_str).read_text(encoding="utf-8").strip())
            except (OSError, ValueError) as exc:
                print(f"dispatch-sign: cannot read pubkey {pubkey_ref}: {exc}", file=sys.stderr)
                return 2
        else:
            seed, err = _seed(Path(key_ref) if key_ref else None)
            if err:
                print(f"dispatch-sign: {err}", file=sys.stderr)
                return 2
            pub_bytes = ed.publickey(seed)
        try:
            sig = base64.b64decode(env_obj["sig_b64"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            print(f"dispatch-sign: malformed signature in envelope: {exc}", file=sys.stderr)
            return 2
        if not ed.checkvalid(sig, canonical_record(rec_obj), pub_bytes):
            print("dispatch-sign: signature verification FAILED", file=sys.stderr)
            return 2
    return 0


def sign_transcript(key: Path | None, transcript: Path, out: Path | None = None) -> int:
    """Wrap a verdict object in the envelope. Every transcript field must be PRESENT (None is a
    legal value for none of them: an absent verdict list or exit code is nothing to sign)."""
    seed, err = _seed(key)
    if err:
        print(f"dispatch-sign: {err}", file=sys.stderr)
        return 1
    try:
        record = json.loads(transcript.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"dispatch-sign: cannot read a verdict object from {transcript}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(record, dict):
        print(f"dispatch-sign: {transcript} is not a JSON object", file=sys.stderr)
        return 1
    if "sig_b64" in record and "record" in record:
        print(f"dispatch-sign: {transcript} is already an envelope — sign the verdict object, "
              "not a signed one", file=sys.stderr)
        return 1
    missing = [k for k in TRANSCRIPT_FIELDS if record.get(k) is None]
    if missing:
        print(f"dispatch-sign: verdict object is missing {missing} — refusing to sign an absence "
              f"(want every one of {list(TRANSCRIPT_FIELDS)})", file=sys.stderr)
        return 1
    mismatch = toolchain_mismatch(record)
    if mismatch:
        print(f"dispatch-sign: {mismatch}", file=sys.stderr)
        return 1
    text = json.dumps(envelope(seed, record, TRANSCRIPT_FIELDS), indent=2)
    if out is None:
        print(text)
    else:
        out.write_text(text + "\n", encoding="utf-8")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Coordinator dispatch-record signer (#135).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="generate an Ed25519 keypair")
    g.add_argument("--out", required=True, help="path for the private seed; <out>.pub gets the pubkey")
    g.add_argument("--in-repo-ok", action="store_true",
                   help="allow writing the seed inside a git work tree even when it is not ignored")

    s = sub.add_parser("sign", help="sign a dispatch record")
    s.add_argument("--key", default=None, help="private seed file from gen-key (or OPEN_FLEET_SIGNING_SEED / ORCA_DISPATCH_SIGNING_SEED)")
    s.add_argument("--manifest-id", required=True, help="the unit/manifest id this dispatch binds")
    s.add_argument("--contract-digest", required=True, help="sha256:… of the frozen contract")
    s.add_argument("--unit-class", required=True, help="mutation | report-only | planning")
    s.add_argument("--lighting", default=None, help="lit | dark-eligible (optional)")
    # #311: the negative-control inputs. Optional — sign them when the coordinator knows the
    # control up front; omitted, the gate binds them to base_sha..head_sha instead (#280).
    s.add_argument("--nc-path", action="append", default=None, dest="nc_paths", metavar="PATH",
                   help="a path the negative control must revert; repeatable. Signed as a SET, so "
                        "the order given here does not matter (optional)")
    s.add_argument("--nc-command", default=None,
                   help="the criterion-bound command the control must turn RED (optional)")
    s.add_argument("--nc-artifact-sha256", default=None, metavar="HEX",
                   help="sha256 of the control's artifact CONTENT, so the evidence itself is "
                        "pinned and not just its path (optional)")
    # Review P2: the lane flags verify.py takes from argv / ORCA_* — signed, a worker cannot add
    # the review waiver, move the lane, or drop the executed control underneath the record.
    s.add_argument("--no-gh", action="store_const", const=True, default=None, dest="no_gh",
                   help="authorize the offline/no-gh review lane (optional; unsigned, the gate "
                        "refuses a --no-gh run)")
    s.add_argument("--lane", default=None, choices=["A", "B", "0"],
                   help="the unit's lane (gate-classification.md) (optional; unsigned, the gate "
                        "refuses a --lane run)")
    s.add_argument("--execute-nc", action="store_const", const=True, default=None,
                   dest="execute_nc",
                   help="require the gate to EXECUTE the negative control (optional)")
    s.add_argument("--profile", default=None,
                   help="child execution profile (ro | rw | danger) (#590)")
    s.add_argument("--parent-profile", default=None, dest="parent_profile",
                   help="parent execution profile (ro | rw | danger) for monotonic narrowing (#590)")

    v = sub.add_parser("verify", help="verify a dispatch record and monotonic privilege narrowing (#590)")
    v.add_argument("record_pos", nargs="?", default=None, help="optional signed envelope path or JSON")
    v.add_argument("--record", "--envelope", dest="record", default=None, help="signed envelope path or JSON")
    v.add_argument("--pubkey", default=None, help="public key file or hex")
    v.add_argument("--key", default=None, help="private seed file (or OPEN_FLEET_SIGNING_SEED / ORCA_DISPATCH_SIGNING_SEED)")
    v.add_argument("--profile", default=None, help="child execution profile (ro | rw | danger)")
    v.add_argument("--parent-profile", default=None, dest="parent_profile",
                   help="parent execution profile (ro | rw | danger) for monotonic narrowing")

    t = sub.add_parser("sign-transcript",
                       help="sign a verify.py verdict object (#281/#386) — only one YOU produced: "
                            "its toolchain.files must hash the scripts beside this signer")
    t.add_argument("--key", default=None, help="private seed file from gen-key (or OPEN_FLEET_SIGNING_SEED / ORCA_DISPATCH_SIGNING_SEED)")
    t.add_argument("--transcript", required=True,
                   help="the verdict object verify.py wrote with --transcript-out (unsigned), from "
                        "a run you made with the scripts beside this signer — the signer re-hashes "
                        "toolchain.files and refuses any other verifier's verdict (h409 O-2.4)")
    t.add_argument("--out", default=None,
                   help="write the envelope here instead of stdout (e.g. the run's own directory)")

    args = ap.parse_args(argv)
    if args.cmd == "gen-key":
        return gen_key(Path(args.out), in_repo_ok=args.in_repo_ok)
    if args.cmd == "sign-transcript":
        return sign_transcript(Path(args.key) if args.key else None, Path(args.transcript),
                               Path(args.out) if args.out else None)
    if args.cmd == "verify":
        rec_ref = args.record if args.record is not None else args.record_pos
        return verify_dispatch(
            rec_ref,
            pubkey_ref=args.pubkey,
            key_ref=args.key,
            profile=args.profile,
            parent_profile=args.parent_profile,
        )
    record = {
        "manifest_id": args.manifest_id,
        "contract_digest": args.contract_digest,
        "unit_class": args.unit_class,
        "lighting": args.lighting,
        "nc_paths": args.nc_paths,
        "nc_command": args.nc_command,
        "nc_artifact_sha256": args.nc_artifact_sha256,
        "no_gh": args.no_gh,
        "lane": args.lane,
        "execute_nc": args.execute_nc,
        "profile": args.profile,
        "parent_profile": args.parent_profile,
    }
    return sign(Path(args.key) if args.key else None, record, parent_profile=args.parent_profile)


if __name__ == "__main__":
    sys.exit(main())
