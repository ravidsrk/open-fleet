"""Process containment for paid calls: find every process of a call, wherever it went.

Every process of a call carries `OF_CALL_ID=<its tag>` in its environment. A descendant that calls
setsid() leaves its call's process group and, once its parent exits, its process tree too, but it
keeps the marker, so a sweep finds it by the marker. `sweep` SIGKILLs everything carrying a tag,
every member of the given groups and every descendant of any of them, until a fresh scan finds
none; it fails closed when one survives or when the process table cannot be read.
`containment_problem` is the host check a paid live run makes before it reserves anything: probes
in sessions of their own, carrying a marker, must show up in the process table by that marker.
`live_disabled` is the refusal every paid live entry point gives first: the live tier runs only
inside a container the live harness started (scripts/live_container.py; PR #668), which
`harness_problem` recognises by a container marker, the launcher's attestation and the strong probe.

One helper, shared: scripts/_ablation_run.py (#606/#657, its watchdog and contained_run),
first_run.py and the WIP-curve runner use this module. It ships in the runtime bundle, which
first_run.py is part of (PR #668 review: the sweep moved here from _ablation_run.py, unchanged
but for the injectable process-table reader `table`).

Discovery is only as good as the table: Linux reads /proc/<pid>/environ, which shows every process
this user owns; elsewhere `ps -E`, which on macOS cannot read an Apple system binary's environment
(/bin/sh, /bin/sleep), so a detached shell is invisible there. The probe can test for exactly that.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# Every process of a call carries `OF_CALL_ID=<its tag>` in its environment, wherever it goes: a
# descendant that calls setsid() leaves the call's process group but keeps the marker (K4).
CALL_MARKER = "OF_CALL_ID"
# A second marker, alongside the call's: one dispatch of a run carries its own tag, so what that one
# dispatch left behind can be found and ended before its call is settled (PR #668 review).
DISPATCH_MARKER = "OF_DISPATCH_TAG"

# The paid live tier runs only inside the container-based live harness (PR #668, the owner's
# decision; scripts/live_container.py). Every paid entry point asks live_disabled() first, before
# it reads or reserves anything: wip_curve.py run --worker live, ablation.py run --tier live,
# hint_replay.py --live --tier live, eval.py run --suite trajectories --tier live and
# first_run.py --worker live. Outside a container the launcher started each refuses, exit 2, with
# this message and the reason. No flag, environment variable or argument lifts it on a plain host.
LIVE_DISABLED = ("live runs are disabled outside the container-based live harness (PR #668; "
                 "scripts/live_container.py): nothing was read, reserved or run")
# How a container shows it is the harness's (scripts/live_container.py writes what this reads): a
# container runtime's marker; the launcher's attestation, mounted read-only, holding a fresh nonce
# the launch receipt records; and the container's hostname, which the launcher sets to
# HARNESS_HOSTNAME + that nonce. The nonce ties a container to its launch: an attestation left from
# another launch, or copied into another container, names a nonce that is not this hostname's.
CONTAINER_MARKERS = ("/.dockerenv", "/run/.containerenv")
ATTESTATION = "/run/open-fleet/live-attestation.json"
ATTESTATION_SCHEMA = "open-fleet.live-attestation/1"
HARNESS_HOSTNAME = "of-live-"


def live_disabled():
    """Why a paid live run does not start here, or None inside the live harness's container
    (harness_problem). Each entry point asks this function rather than read the constant so that
    the live machinery's own tests can replace it in their process (the Python-level seam the host
    probe uses); nothing in production can."""
    why = harness_problem()
    return None if why is None else f"{LIVE_DISABLED}; here: {why}"


def environ_of(pid):
    """A Linux process's environment as it was started (empty when it is not ours to read)."""
    try:
        raw = Path("/proc", str(pid), "environ").read_bytes()
    except OSError:
        return ()
    return tuple(raw.decode("utf-8", errors="replace").split("\0"))


def process_table():
    """{pid: (ppid, pgid, environment entries)} for every live process this user can see; a zombie
    runs nothing and is left out. Linux reads /proc; elsewhere `ps -E` lists each of this user's
    own processes with the environment it started with (others' read as empty). OSError when the
    table cannot be read: a sweep that cannot see cannot vouch for anything."""
    table = {}
    if os.path.isdir("/proc/self"):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                stat = Path("/proc", entry, "stat").read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue  # gone since the listing
            fields = stat.rsplit(")", 1)[-1].split()  # after `pid (comm)`: comm may hold spaces
            if len(fields) > 2 and fields[0] not in ("Z", "X") and fields[1].isdigit() and fields[2].isdigit():
                table[int(entry)] = (int(fields[1]), int(fields[2]), environ_of(entry))
        return table
    scan = subprocess.Popen(["ps", "-A", "-E", "-ww", "-o", "pid=,ppid=,pgid=,stat=,command="],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
                            start_new_session=True)
    try:
        out, _err = scan.communicate(timeout=30)
    except subprocess.TimeoutExpired as err:
        scan.kill()
        scan.wait()
        raise OSError("ps did not answer within 30 s") from err
    if scan.returncode != 0:
        raise OSError(f"ps exited with status {scan.returncode}")
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit() \
                and not parts[3].startswith("Z"):
            # `command` is the argv then (-E) the environment, space-separated: a marker is a token.
            env = tuple(parts[4].split()) if len(parts) > 4 else ()
            table[int(parts[0])] = (int(parts[1]), int(parts[2]), env)
    table.pop(scan.pid, None)  # the scan itself is nobody's call
    return table


def call_processes(table, roots=(), groups=(), exclude=(), tag=None, marker=CALL_MARKER):
    """A call's live pids in `table`: every process carrying its `tag`, every member of `groups`,
    every one of `roots`, and every descendant of any of them -- minus `exclude` and this process,
    which never sweeps itself."""
    token = f"{marker}={tag}" if tag else None
    children = {}
    for pid, (ppid, _pgid, _env) in table.items():
        children.setdefault(ppid, []).append(pid)
    stack = [pid for pid, (_ppid, pgid, env) in table.items() if pgid in groups or (token and token in env)]
    stack += [pid for pid in roots if pid in table]
    found = set()
    while stack:
        pid = stack.pop()
        if pid not in found:
            found.add(pid)
            stack.extend(children.get(pid, ()))
    return found - set(exclude) - {os.getpid()}


def sweep(roots=(), groups=(), exclude=(), wait_s=10.0, tag=None, table=None, marker=CALL_MARKER):
    """SIGKILL a call's processes (call_processes) until a fresh scan finds none: True. False when
    one survives `wait_s`, or when the process table cannot be read (fail closed). `table` is the
    process-table reader (process_table when None), injected by a caller or a test."""
    read = table or process_table
    deadline = time.monotonic() + wait_s
    while True:
        try:
            left = call_processes(read(), roots, groups, exclude, tag, marker)
        except OSError:
            return False
        if not left:
            return True
        for pid in left:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)


def containment_problem(system_binary=True, table=None):
    """Why process discovery cannot contain a call on this host, or None (#657 review W1). Probes
    in sessions of their own, carrying a call marker, must show up in the process table by that
    marker. Checked before a paid run reserves anything: where a sandbox denies `ps`, or the table
    hides environments, a call's escaped processes could never be found. `table` is the
    process-table reader, injected by a caller or a test."""
    # The strong probe, every paid runner's default (PR #668 review): a system binary such as a
    # worker's shell starts must be discoverable too. macOS's `ps -E` cannot read an Apple system
    # binary's environment (/bin/sh, /bin/sleep) while it reads a Python's, so a Python probe alone
    # vouches for a table blind to a detached shell. With no system binary to probe with, nothing is
    # proven. `system_binary=False` (the Python probe alone) is for tests of the probe itself.
    tag = secrets.token_hex(16)
    sleep = shutil.which("sleep", path="/bin:/usr/bin") if system_binary else None
    if system_binary and not sleep:
        return "no system binary (sleep) to probe with: containment of a detached shell cannot be proven"
    argvs = [[sys.executable, "-c", "import time; time.sleep(60)"]] + ([[sleep, "60"]] if sleep else [])
    probes = []
    try:
        for argv in argvs:
            probes.append(subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, env=dict(os.environ, **{CALL_MARKER: tag}),
                                           start_new_session=True))
    except OSError as err:
        for probe in probes:
            probe.kill()
            probe.wait()
        return f"a probe could not start: {err}"
    try:
        deadline = time.monotonic() + 3
        while True:
            try:
                found = call_processes((table or process_table)(), tag=tag)
            except OSError as err:
                return f"the process table cannot be read: {err}"
            if found == {probe.pid for probe in probes}:
                return None
            if time.monotonic() > deadline:
                hidden = [Path(probe.args[0]).name for probe in probes if probe.pid not in found]
                return f"the process table does not show a call's {CALL_MARKER} marker (on {', '.join(hidden)})"
            time.sleep(0.05)
    finally:
        for probe in probes:
            probe.kill()
            probe.wait()


def harness_problem(root="/", hostname=None, probe=None):
    """Why this process is not inside a container the live harness started, or None when it is.

    All three must hold, checked in this order so that a plain host refuses having read two paths
    and launched nothing: a container marker (CONTAINER_MARKERS); the launcher's attestation at
    ATTESTATION, whose 32-hex nonce makes this container's hostname HARNESS_HOSTNAME + nonce; and
    the strong probe (containment_problem) passing, which it does on Linux. `root`, `hostname` and
    `probe` are the Python-level seam for its tests: the file system root, the UTS hostname
    (os.uname) and the probe. This guards against accidents on a host, not against an operator who
    fakes a container: with root, anyone can write a marker, an attestation and a hostname."""
    base = Path(root)
    if not any((base / marker.lstrip("/")).exists() for marker in CONTAINER_MARKERS):
        return "no container marker (/.dockerenv or /run/.containerenv): this is no container"
    try:
        doc = json.loads((base / ATTESTATION.lstrip("/")).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return f"no live-harness attestation at {ATTESTATION}: scripts/live_container.py did not start this container"
    except (OSError, ValueError) as err:
        return f"the live-harness attestation at {ATTESTATION} cannot be read ({type(err).__name__})"
    nonce = doc.get("nonce") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != ATTESTATION_SCHEMA or not isinstance(nonce, str) \
            or len(nonce) != 32 or nonce.strip("0123456789abcdef"):
        return f"the attestation at {ATTESTATION} names no nonce"
    name = os.uname().nodename if hostname is None else hostname
    if name != HARNESS_HOSTNAME + nonce:
        return "the attestation's nonce is not this container's (its hostname): it is from another launch"
    why = (probe or containment_problem)()
    return f"the strong containment probe fails: {why}" if why else None
