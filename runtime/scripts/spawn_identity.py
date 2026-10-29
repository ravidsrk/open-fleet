#!/usr/bin/env python3
"""Who is spawning: an identity that survives a scrubbed environment (W4-04, Codex round 3).

spawn_worker.sh capped a worker by what its environment said (a profile variable, or the pane
handle `ORCA_TERMINAL_HANDLE` keyed into the spawn registry). A harness that drops `ORCA_*` (Codex's
`shell_environment_policy` does, as ordinary behaviour) left a `ro` worker with nothing to say,
and a missing pane handle read as "coordinator": uncapped. Identity here comes from the process
tree instead, which no environment rewrites. It identifies only processes that descend from the
pane: one that daemonized out of it, a command a harness runs from a process started outside the
pane, or a spawn inside another pid namespace (whose /proc shows other pids) is not identified
by it. Whether any harness does that as ordinary behaviour is unwitnessed.

- a ROOT is a worker's pane process, recorded at registration as `<pid>.<start>` (the start
  time defeats pid reuse) with the worker's profile. It is found by the pane handle in its
  INITIAL environment (`/proc/<pid>/environ`, else `ps -E`), which the pane process keeps
  whatever its children later drop. Every process the worker runs descends from it;
- a HOST is a root's parent (the pty host, the tmux pane's shell): a caller under one is inside
  a provider's process tree;
- an ANCHOR is a process of the coordinator that launched a worker while uncapped: its own
  ancestors below the nearest one it shares with the worker. A worker can never descend from
  one. An anchor stops counting the moment a live root or a host turns out to descend from it.

record-root exits 0 when it recorded the pane's root; 2 when it recorded a root it could not
verify (a carrier's start time or parent unreadable, or a root with no parent to record as its
host found by a scan that was not complete: possibly a carrier that escaped a pane whose own
process could not be read); 3 when a COMPLETE scan found no process carrying the handle (the
worker is not a local process: it exited, runs remotely or in another uid's container, or the
backend is a dry run); 1 when nothing was found and the scan was not complete, or nothing could
be read. A scan is complete only when every process of this uid that could be this launch's pane
was read. A process is this uid's when ANY of the real, effective, saved and filesystem uids on
the `Uid:` line of /proc/<pid>/status is this uid (a pane that went non-dumpable or runs a setuid
program included), never by the owner of /proc/<pid> or its files (the effective uid alone, and
root for a non-dumpable process's files; Codex round 10); one none of whose uids is this uid is
another user's and is skipped; one whose status cannot be read or holds no single well-formed
`Uid:` line leaves the scan incomplete (1, never 3): under hidepid=1 another user's status cannot
be read, so no scan there is complete; under hidepid=2 a non-dumpable process of this uid is not
listed at all (not covered). An environment of this uid's process that stays unreadable for any
reason but the process being gone (EACCES from a non-dumpable process, EIO; re-read for a moment
first, since a process caught exiting answers EACCES briefly) makes it incomplete too. A process
that vanishes mid-scan is gone, not unknown. With `--since PID` (spawn_worker.sh passes itself),
an unreadable process that started before PID is not counted: it cannot be a pane this launch
created, so a runtime that hands a launch a pre-existing pane is not covered
there. Without /proc, `ps -E` omits an environment it may not read without saying so, so no scan
there is complete: finding nothing is 1, never 3. Every read elsewhere is tri-state too: a failed
read is UNKNOWN, never "absent", and whoami exits 1 on one (spawn_worker.sh then caps at ro).

Registry (under spawn_worker.sh's `~/.open-fleet/spawn-profiles/`): `.roots/<key>` holds
`<profile> <handle>`, `.hosts/<key>` and `.anchors/<key>` are markers, and `.pending/r.*` are
spawn_worker.sh's launch reservations (`<profile> <launcher handle> <launcher pid> <launcher
start>`). Standard library only.

  whoami --registry DIR --pid PID          what identifies PID (lines, see `whoami`)
  record-root --registry DIR --handle H --profile P [--launcher PID] [--since PID] [--wait SECS]
      find H's pane root, record it and its host, and (with --launcher) the launcher's anchors
"""
import sys

# W3-01: `python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib, so a committed
# sibling named like a stdlib module would BE that module here. Drop that entry before any other
# import (no `from __future__` in this file for that reason); `os` is read from sys.modules,
# loaded at start-up. spawn_worker.sh also runs this with `python3 -I`.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

PROC = Path("/proc")
HANDLE_VARS = ("ORCA_TERMINAL_HANDLE", "OPEN_FLEET_TERMINAL_HANDLE")
PROFILES = ("ro", "rw", "danger")
_KEY = re.compile(r"[1-9][0-9]*\.[0-9]+\Z")
_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*\Z")
MAX_DEPTH = 256


class Unknown(RuntimeError):
    """A read that failed for any reason but the process (or file) being gone: the answer is
    UNKNOWN, never "absent", and every caller fails closed on it (Codex round 4)."""


class ScanUnavailable(Unknown):
    """No way to read other processes' environments on this host: nothing found proves nothing."""


class NoProcess(RuntimeError):
    """The scan was complete and no running process carries the handle: no local worker."""


# Absent, not unknown: the process or file is not there (a path through a regular file cannot be).
GONE = (FileNotFoundError, ProcessLookupError, NotADirectoryError)


def _ps(pid: int, field: str) -> str | None:
    """`ps -o <field>= -p <pid>`: the value, None when there is no such process, Unknown when ps
    cannot answer at all."""
    try:
        out = subprocess.run(["ps", "-o", f"{field}=", "-p", str(pid)], capture_output=True, text=True,
                             timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise Unknown(f"ps cannot answer: {exc}") from None
    text = " ".join(out.stdout.split())
    if out.returncode == 0 and text:
        return text
    if out.returncode == 1 and not text:
        return None  # BSD and procps ps: no such process
    raise Unknown(f"ps -p {pid} exited {out.returncode}")


def stat(pid: int) -> tuple[int, str] | None:
    """(ppid, start token) of a live pid; None when it is gone; Unknown when it cannot be read."""
    if PROC.is_dir():
        try:
            raw = (PROC / str(pid) / "stat").read_text()
        except GONE:
            return None
        except OSError as exc:
            raise Unknown(f"/proc/{pid}/stat: {exc.strerror or exc}") from None
        fields = raw[raw.rfind(")") + 2:].split()
        try:
            return int(fields[1]), fields[19]
        except (IndexError, ValueError):
            raise Unknown(f"/proc/{pid}/stat has an unexpected shape") from None
    ppid = _ps(pid, "ppid")
    lstart = _ps(pid, "lstart") if ppid is not None else None
    if ppid is None or lstart is None:
        return None
    try:
        start = str(int(time.mktime(time.strptime(lstart, "%a %b %d %H:%M:%S %Y"))))
        return int(ppid), start
    except ValueError:
        raise Unknown(f"ps answered an unexpected shape for {pid}") from None


def _proc_state(pid: int) -> str | None:
    """The state letter in /proc/<pid>/stat; None when the process is gone; Unknown when unread."""
    try:
        raw = (PROC / str(pid) / "stat").read_text()
    except GONE:
        return None
    except OSError as exc:
        raise Unknown(f"/proc/{pid}/stat: {exc.strerror or exc}") from None
    return raw[raw.rfind(")") + 2:][:1] or None


# A zombie (Z) or dead (X) process has exited: it runs nothing and forks nothing, its children were
# reparented when it exited, and its environment is gone, so reading it answers EACCES. It is
# ABSENT, not unknown: counting it as unreadable made a busy host's scans inconclusive (an exited
# command its parent had not reaped yet), and kept reservations of workers that had exited.
EXITED = ("Z", "X")


def key(pid: int) -> str | None:
    st = stat(pid)
    return f"{pid}.{st[1]}" if st else None


def alive(k: str) -> bool | None:
    """True, False (gone, or its pid now belongs to another process), or None (unknown)."""
    try:
        return key(int(k.split(".", 1)[0])) == k
    except Unknown:
        return None


def chain(pid: int, *, allow_hidden: bool = False) -> list[str]:
    """The keys of pid and every ancestor, nearest first (pid 1 and the kernel excluded). Raises
    Unknown unless the walk reaches the top: an ancestor that cannot be read could be a recorded
    worker root. A parent that is not visible while its child still names it is another user's
    process hidden from /proc (hidepid); the walk may stop there only when `allow_hidden` (no
    live root could be above it, so nothing can be missed)."""
    out: list[str] = []
    while pid > 1:
        if len(out) >= MAX_DEPTH:
            raise Unknown("an ancestry deeper than the walk allows")
        st = stat(pid)
        if st is None:
            if not out:
                raise Unknown(f"process {pid} is not running")
            child = int(out[-1].split(".", 1)[0])
            again = stat(child)
            if again is None:
                raise Unknown(f"process {child} vanished mid-walk")
            if again[0] != pid:
                pid = again[0]  # the parent exited and the child was reparented: follow it
                continue
            if allow_hidden:
                break
            raise Unknown(f"ancestor {pid} of {child} cannot be read")
        out.append(f"{pid}.{st[1]}")
        pid = st[0]
    return out


def _read_environ(pid: int) -> bytes:
    """/proc/<pid>/environ: the process's INITIAL environment. Raises OSError as the read does."""
    return (PROC / str(pid) / "environ").read_bytes()


def _read_status(pid: int) -> str:
    """/proc/<pid>/status. Raises OSError as the read does."""
    return (PROC / str(pid) / "status").read_text(encoding="utf-8", errors="replace")


_UID_LINE = re.compile(r"Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*\Z")


def _uids(pid: int) -> tuple[int, ...] | None:
    """(real, effective, saved, filesystem) uid of a process: its CREDENTIALS, from the one `Uid:`
    line of /proc/<pid>/status, which stays readable when the process is non-dumpable. Never the
    owner of /proc/<pid> or of its files: that is the effective uid alone (a pane running a setuid
    program shows root there while its real uid is this one), and root for every file of a
    non-dumpable process (Codex round 10). None when the process is gone; Unknown when the file
    cannot be read or does not hold exactly one `Uid:` line of four uids."""
    try:
        text = _read_status(pid)
    except GONE:
        return None
    except OSError as exc:
        raise Unknown(f"/proc/{pid}/status: {exc.strerror or exc}") from None
    lines = [line for line in text.split("\n") if line.startswith("Uid:")]
    match = _UID_LINE.match(lines[0]) if len(lines) == 1 else None
    if match is None:
        raise Unknown(f"/proc/{pid}/status does not name its credentials (one Uid: line of four uids)")
    return tuple(int(u) for u in match.groups())


def _handles_in(raw: bytes) -> set[str]:
    found = set()
    for item in raw.split(b"\0"):
        name, _, value = item.partition(b"=")
        if name.decode("latin-1") in HANDLE_VARS:
            found.add(value.decode("utf-8", "replace"))
    return found


UNREADABLE_SETTLE_SECS = 0.25
VANISHED_ROUNDS = 5


def _scan_proc(handle: str, since: int | None) -> tuple[list[int], bool]:
    """(pids whose initial environment names `handle`, complete?) over /proc. A process is this
    uid's when ANY of its credentials (`_uids`: real, effective, saved, filesystem) is this uid, so
    a pane that went non-dumpable or runs a setuid program is still read; one none of whose uids is
    this one is another user's and is skipped. Incomplete when /proc cannot be listed, when a
    process's credentials cannot be read or parsed, or when a process of this uid has an
    environment that stays unreadable (non-dumpable, EIO) and may be this launch's (it started at
    or after `since`, or its start is unknown). An unreadable environment is read again for up to
    UNREADABLE_SETTLE_SECS first: a process caught exiting answers EACCES for a moment and then is
    gone, and on a busy host (other sessions' commands) that moment is common. A process that has
    exited but is not yet reaped (a zombie, EXITED) answers EACCES for as long as its parent
    leaves it: it is absent, not unreadable.

    A process that vanishes mid-scan is GONE, not unknown. A carrier it forked just before it
    exited is reparented out of the pane's live tree (the daemonized-out residual); the scan
    re-lists up to VANISHED_ROUNDS times to examine such children, as a best effort, but a host
    whose processes never stop coming and going does not make it incomplete."""
    uid = os.getuid()
    examined: set[int] = set()
    found: list[int] = []
    complete, vanished, rounds = True, True, 0

    def judge(pid: int, raw: bytes) -> None:
        if handle in _handles_in(raw):
            found.append(pid)

    while vanished and rounds < VANISHED_ROUNDS:
        rounds += 1
        vanished = False
        unreadable: list[int] = []
        try:
            listing = [int(p.name) for p in PROC.iterdir() if p.name.isdigit()]
        except OSError as exc:
            raise ScanUnavailable(f"cannot list /proc: {exc}") from None
        for pid in listing:
            if pid in examined:
                continue
            examined.add(pid)
            try:
                uids = _uids(pid)
            except Unknown:
                complete = False  # whose it is cannot be told: it could be this uid's pane
                continue
            if uids is None:
                vanished = True
                continue
            if uid not in uids:
                continue  # no credential of it is this uid: another user's process
            try:
                raw = _read_environ(pid)
            except GONE:
                vanished = True
                continue
            except OSError:  # EACCES (non-dumpable), EIO, anything: UNKNOWN, never "no handle"
                try:
                    st, state = stat(pid), _proc_state(pid)
                except Unknown:
                    complete = False
                    continue
                if st is None or state is None:
                    vanished = True
                elif state in EXITED:
                    continue  # exited, not yet reaped: absent (EXITED)
                elif since is None or int(st[1]) >= since:
                    unreadable.append(pid)
                continue
            judge(pid, raw)
        settle = time.monotonic() + UNREADABLE_SETTLE_SECS
        while unreadable:
            for pid in list(unreadable):
                try:
                    raw = _read_environ(pid)
                except GONE:
                    unreadable.remove(pid)
                    vanished = True
                    continue
                except OSError:
                    try:
                        if _proc_state(pid) in EXITED + (None,):
                            unreadable.remove(pid)  # it exited while we waited: absent
                    except Unknown:
                        pass
                    continue
                unreadable.remove(pid)
                judge(pid, raw)
            if not unreadable or time.monotonic() >= settle:
                break
            time.sleep(0.01)
        if unreadable:
            complete = False
    return sorted(found), complete


def processes_with_handle(handle: str, since: int | None = None) -> tuple[list[int], bool]:
    """(every pid whose INITIAL environment names `handle` as its pane, complete?)."""
    if PROC.is_dir():
        return _scan_proc(handle, since)
    try:  # BSD/macOS ps: -E appends the environment to the command (unwitnessed; best effort)
        out = subprocess.run(["ps", "-A", "-ww", "-E", "-o", "pid=,command="], capture_output=True,
                             text=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanUnavailable(f"cannot list process environments: {exc}") from None
    if out.returncode != 0:
        raise ScanUnavailable("cannot list process environments (ps -E failed)")
    want = re.compile(r"(?:^| )(?:%s)=%s(?: |$)" % ("|".join(HANDLE_VARS), re.escape(handle)))
    pids = []
    for line in out.stdout.splitlines():
        head, _, rest = line.strip().partition(" ")
        if head.isdigit() and want.search(rest):
            pids.append(int(head))
    # ps -E silently omits an environment it may not read, so its absence proves nothing.
    return sorted(pids), False


class Registry:
    """The registry's directories. A directory that is not there is empty; one that cannot be
    read is Unknown, never empty (Codex round 4)."""

    def __init__(self, path: str):
        self.root = Path(path)

    def _dir(self, name: str) -> Path:
        return self.root / name

    def entries(self, name: str, pattern=_KEY) -> list[str]:
        try:
            return sorted(p.name for p in self._dir(name).iterdir() if pattern.match(p.name))
        except GONE:
            return []
        except OSError as exc:
            raise Unknown(f"cannot list {self._dir(name)}: {exc.strerror or exc}") from None

    def read(self, name: str, k: str) -> str | None:
        """The entry's text; None when it is gone; Unknown when it cannot be read."""
        try:
            return (self._dir(name) / k).read_text(encoding="utf-8", errors="replace")
        except GONE:
            return None
        except OSError as exc:
            raise Unknown(f"cannot read {self._dir(name) / k}: {exc.strerror or exc}") from None

    def write(self, name: str, k: str, text: str) -> None:
        d = self._dir(name)
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".w.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, d / k)

    def drop(self, name: str, k: str) -> None:
        try:
            (self._dir(name) / k).unlink()
        except OSError:
            pass

    def live(self, name: str) -> list[str]:
        """Entries whose process is running, or whose liveness cannot be told (kept: failing
        closed); the ones that are certainly gone are pruned."""
        out = []
        for k in self.entries(name):
            state = alive(k)
            if state is False:
                self.drop(name, k)
            else:
                out.append(k)
        return out

    def live_roots(self) -> dict[str, str]:
        """key -> profile of every recorded root that may still be running."""
        out = {}
        for k in self.live(".roots"):
            text = self.read(".roots", k)
            if text is not None:
                out[k] = _profile(text)
        return out


def _profile(text: str) -> str:
    word = (text.split() or ["ro"])[0]
    return word if word in PROFILES else "invalid"


def whoami(reg: Registry, pid: int) -> list[str]:
    """Lines: ROOT <profile> <key> per recorded root among pid's ancestors; INTREE yes|no;
    ANCHORED yes|no; LIVE <profile> per live root anywhere; RESERVATION <profile> <inflight> <path>
    per open launch reservation this caller is not exempt from; SELF <key>. Any read that fails
    for a reason but absence raises Unknown: spawn_worker.sh then caps the caller at ro."""
    # Reservations FIRST: a launch records its root before it drops its reservation, so one gone
    # from this snapshot means its root (if this process has one) is readable below.
    snapshot = []
    for name in reg.entries(".pending", re.compile(r"r\.")):
        text = reg.read(".pending", name)
        if text is not None:  # gone: resolved between the listing and the read
            snapshot.append((reg._dir(".pending") / name, text.split()))
    live = reg.live_roots()
    mine = chain(pid, allow_hidden=not live)
    if not mine:
        raise Unknown("cannot read this process's ancestry")
    ancestors = set(mine)
    lines = [f"ROOT {prof} {k}" for k, prof in live.items() if k in ancestors]
    hosts = reg.live(".hosts")
    lines.append("INTREE " + ("yes" if ancestors & set(hosts) else "no"))
    # An anchor counts only while it is certainly alive and no live root and no host descends from
    # it; a root or host whose ancestry cannot be read could shadow any of them, so then none counts.
    try:
        shadowed: set[str] | None = set()
        for k in list(live) + hosts:
            shadowed.update(chain(int(k.split(".", 1)[0]), allow_hidden=True))
    except Unknown:
        shadowed = None
    anchors = [k for k in reg.live(".anchors") if alive(k) is True]
    anchored = shadowed is not None and any(k in ancestors and k not in shadowed for k in anchors)
    lines.append("ANCHORED " + ("yes" if anchored else "no"))
    lines += [f"LIVE {prof}" for prof in live.values()]
    for path, fields in snapshot:
        prof = fields[0] if fields and fields[0] in PROFILES else ("ro" if not fields else "invalid")
        launcher = f"{fields[2]}.{fields[3]}" if len(fields) >= 4 and _KEY.match(f"{fields[2]}.{fields[3]}") else None
        # In flight unless its launcher is certainly gone: an unknown launcher is waited on.
        inflight = launcher is not None and alive(launcher) is not False
        # The coordinator's own launches do not cap it: exempt only when it is anchored AND does
        # not descend from the launch in question (a worker that launch started might, while
        # the launch is still running).
        if anchored and launcher is not None and launcher not in ancestors:
            continue
        lines.append(f"RESERVATION {prof} {1 if inflight else 0} {path}")
    lines.append(f"SELF {mine[0]}")
    return lines


def record_root(reg: Registry, handle: str, profile: str, launcher: int | None, wait: float,
                since_pid: int | None = None) -> tuple[list[str], bool]:
    """(lines, verified?). A carrier FOUND is the pane's process tree: it is recorded, and the
    rest of the scan no longer decides anything, since another carrier of this handle outside that
    tree would have to have escaped it (the daemonized-out residual) — except that a found root
    with no parent to record as its host, from a scan that was not complete, may be just such an
    escapee from a pane whose own process could not be read: unverified. Nothing found: NoProcess
    when the scan was complete, Unknown when it was not (an environment it could not read may be
    the pane's). `since_pid` (the launching spawn) dates the launch: an unreadable process that
    started before it cannot be this launch's pane."""
    if not _HANDLE.match(handle) or profile not in PROFILES:
        raise RuntimeError("not a pane handle or profile")
    since = None
    if since_pid is not None and PROC.is_dir():
        try:
            st = stat(since_pid)
            since = int(st[1]) if st else None
        except (Unknown, ValueError):
            since = None
    deadline = time.monotonic() + wait
    while True:
        found, complete = processes_with_handle(handle, since)
        if found or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    verified = True
    roots = []
    found_set = set(found)
    for pid in found:
        try:
            st = stat(pid)
        except Unknown:
            verified = False  # a carrier whose start time cannot be read cannot be recorded
            continue
        if st is None or st[0] in found_set:
            continue  # gone, or not the topmost process of the pane
        roots.append((pid, st))
    if not roots:
        if complete and verified:
            raise NoProcess(f"no running process carries pane handle {handle}")
        raise Unknown(f"no process could be confirmed to carry pane handle {handle}, and the scan "
                      "was not complete (an environment it could not read, or no /proc to read "
                      "them in)")
    lines = []
    for pid, (ppid, start) in roots:
        k = f"{pid}.{start}"
        reg.write(".roots", k, f"{profile} {handle}\n")
        lines.append(f"ROOT {k}")
        try:
            hk = key(ppid) if ppid > 1 else None
        except Unknown:
            hk, verified = None, False
        if hk:
            reg.write(".hosts", hk, "")
            lines.append(f"HOST {hk}")
        elif not complete:
            verified = False  # no host, from an incomplete scan: maybe an escapee, see above
    if launcher is not None:
        try:
            coordinator = chain(launcher, allow_hidden=True)
            shared = set()
            for pid, _st in roots:
                shared.update(chain(pid, allow_hidden=True))
        except Unknown:
            coordinator = []  # cannot bound the coordinator's processes: anchor none
        for k in coordinator:
            if k in shared:
                break  # the nearest common ancestor and everything above it are not the coordinator's
            reg.write(".anchors", k, "")
            lines.append(f"ANCHOR {k}")
    return lines, verified


def own_proc() -> None:
    """On a /proc host, /proc must be this process's own pid namespace's. A sandbox that unshares
    pids but keeps the host's /proc gives every pid read there to some OTHER process (`--pid $$`
    included), so then nothing here can be answered: Unknown."""
    if not PROC.is_dir():
        return
    try:
        me = os.readlink(PROC / "self")
    except OSError as exc:
        raise Unknown(f"cannot read {PROC}/self: {exc.strerror or exc}") from None
    if me != str(os.getpid()):
        raise Unknown(f"{PROC} belongs to another pid namespace (self is {me}, this process is {os.getpid()})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spawn_identity.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("whoami")
    w.add_argument("--registry", required=True)
    w.add_argument("--pid", type=int, required=True)
    r = sub.add_parser("record-root")
    r.add_argument("--registry", required=True)
    r.add_argument("--handle", required=True)
    r.add_argument("--profile", required=True)
    r.add_argument("--launcher", type=int)
    r.add_argument("--wait", type=float, default=1.0)
    r.add_argument("--since", type=int)
    ns = ap.parse_args(argv)
    reg = Registry(ns.registry)
    verified = True
    try:
        own_proc()
        if ns.cmd == "whoami":
            lines = whoami(reg, ns.pid)
        else:
            lines, verified = record_root(reg, ns.handle, ns.profile, ns.launcher, max(0.0, ns.wait), ns.since)
    except (OSError, RuntimeError) as exc:
        text = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(exc))
        print(f"spawn_identity: {text}", file=sys.stderr)
        return 3 if isinstance(exc, NoProcess) else 1
    print("\n".join(lines))
    return 0 if verified else 2


if __name__ == "__main__":
    raise SystemExit(main())
