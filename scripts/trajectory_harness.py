#!/usr/bin/env python3
"""Record a live agent run as #602 trajectory events: the agent-command prefix of the live arms.

    python3 scripts/trajectory_harness.py [--trajectory-out PATH] [--] <agent command...>

#602's live runner (`eval.py run --suite trajectories --tier live`) and #606's paired runner
(`ablation.py run --harness-cmd ...`) both put this in front of the agent command. It:

1. prepares the cell workspace (its cwd): git-inits it when it is not a repository root, gives
   the repository a local identity with signing off, and commits the materialized state as the
   base the agent starts from;
2. runs the agent in the caller's process group, never a new one: scripts/_ablation_run.py kills
   a cell's whole group on a timeout or an interrupt, and an agent that left it would outlive its
   call. stdin is inherited; stdout is passed through byte for byte (the runners read usage from
   it) and kept; stderr is inherited;
3. as tool results stream past, snapshots the workspace's commits (`git rev-list` from the
   base, every ref and reflog) with every call started by then, so a quiet or wrapped commit is
   attributed to the one shell call that can have made it, and refused when two could;
4. once the agent exits, turns the kept Claude stream-json into #602 events
   (scripts/_trajectories.py, record_stream) and writes them to $ABLATION_OUT/trajectory.jsonl,
   or to --trajectory-out when ABLATION_OUT is unset. A destination is required before the agent
   starts, and a stale recording there is removed first, so a run that records nothing leaves
   nothing to be graded. When the recorder refuses (a commit it cannot attribute, a history it
   cannot replay in order), no recording is written and `<destination>.refused` says why;
5. exits with the agent's exit code (128+N when signal N ended it).

Git isolation. The agent's environment points GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM at the null
device and drops every other GIT_* variable (GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT pairs
inject config too), so the operator's ~/.gitconfig and system config are never read. The
workspace's own config sets commit and tag signing off and names `false` as every signing
program, and GNUPGHOME is an empty directory with no SSH agent socket. A commit the agent makes
is unsigned; one it forces with -S fails rather than reach the operator's key.

Stdlib only. Writes nothing outside the workspace, its private GNUPGHOME and the recording.
"""
import importlib.util
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRAJECTORY_FILE = "trajectory.jsonl"
EXIT_USAGE = 2
# The workspace repository's own config: an identity, and no way to sign.
LOCAL_CONFIG = (("user.name", "trajectory-harness"), ("user.email", "harness@example.invalid"),
                ("commit.gpgsign", "false"), ("tag.gpgsign", "false"),
                ("gpg.program", "false"), ("gpg.ssh.program", "false"),
                ("gpg.x509.program", "false"))
# Never handed to the agent: an SSH or GPG agent could sign for it.
_DROPPED = ("SSH_AUTH_SOCK", "GPG_AGENT_INFO")
BASE_MESSAGE = "base: the cell's materialized initial state (trajectory_harness.py)"
SPILL_BYTES = 16 << 20        # spill captured stream to a temp file above 16 MiB in RAM
MAX_CAPTURE_BYTES = 128 << 20  # hard capture ceiling so runaway stdout cannot fill disk
MAX_LINE_BYTES = 16 << 20      # single line cap for incremental tool_use/tool_result scanning
_GITEXEC = None


def _gitexec():
    global _GITEXEC
    if _GITEXEC is None:
        spec = importlib.util.spec_from_file_location("trajectory_harness_gitexec",
                                                      ROOT / "runtime" / "scripts" / "gitexec.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _GITEXEC = mod
    return _GITEXEC


def isolated_env(environ, gnupghome):
    """The agent's environment: the caller's, with git's global and system config gone, no
    other GIT_* variable, gpg pointed at an empty home, and no Python bytecode written."""
    env = {k: v for k, v in environ.items() if not k.startswith("GIT_") and k not in _DROPPED}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0", GNUPGHOME=str(gnupghome),
               # No bytecode caches for `git add -A` to sweep into a commit: a binary blob
               # refuses the recording, and an interpreter cache is not the agent's work.
               PYTHONDONTWRITEBYTECODE="1")
    return env


def _git(workspace, env, *args):
    gx = _gitexec()
    result = subprocess.run(gx.argv("-C", str(workspace), *args), capture_output=True, text=True,
                            env=gx.custody_env(env), stdin=subprocess.DEVNULL, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def prepare_workspace(workspace, env=None):
    """git-init `workspace` when it is not a repository root, set its local identity and signing
    off, commit whatever is there as the base when it has no commit or uncommitted changes, and
    return the base commit's sha."""
    workspace = Path(workspace)
    if env is None:
        env = isolated_env(os.environ, os.devnull)
    if not (workspace / ".git").exists():
        _git(workspace, env, "init", "-q", "-b", "main")
    for key, value in LOCAL_CONFIG:
        _git(workspace, env, "config", "--local", key, value)
    gx = _gitexec()
    has_head = subprocess.run(gx.argv("-C", str(workspace), "rev-parse", "--verify", "-q", "HEAD"),
                              capture_output=True, env=gx.custody_env(env),
                              stdin=subprocess.DEVNULL, timeout=60).returncode == 0
    if not has_head or _git(workspace, env, "status", "--porcelain", "--untracked-files=all"):
        _git(workspace, env, "add", "-A")
        _git(workspace, env, "commit", "-q", "--allow-empty", "-m", BASE_MESSAGE)
    return _git(workspace, env, "rev-parse", "HEAD").strip()


def parse_args(argv):
    """(trajectory-out or None, agent argv). Harness options come first; `--` or the first word
    that is not one of them starts the agent command, whose own options are never read here."""
    out, i = None, 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            i += 1
            break
        if arg == "--trajectory-out" and i + 1 < len(argv):
            out, i = argv[i + 1], i + 2
        elif arg.startswith("--trajectory-out="):
            out, i = arg.split("=", 1)[1], i + 1
        else:
            break
    return out, argv[i:]


def destination(environ, flag):
    if environ.get("ABLATION_OUT"):
        return Path(environ["ABLATION_OUT"]) / TRAJECTORY_FILE
    return Path(flag) if flag else None


def _engine():
    spec = importlib.util.spec_from_file_location("_trajectories_for_harness",
                                                  ROOT / "scripts" / "_trajectories.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _forward(fd, data, open_):
    """Write all of `data` to `fd` while the reader is there; False once it has gone."""
    view = memoryview(data)
    while open_ and view:
        try:
            view = view[os.write(fd, view):]
        except BrokenPipeError:
            return False
    return open_


def commits_after(workspace, env, base):
    """Every commit after the base, oldest first, across every ref and reflog; None when git
    cannot say (the recorder then attributes only commits a call's output names)."""
    try:
        return _git(workspace, env, "rev-list", "--reverse", "--topo-order", "--all", "--reflog",
                    f"^{base}").split()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return None


def _block_ids(line, kind, block_type, key):
    if f'"{block_type}"'.encode() not in line:
        return []
    try:
        obj = json.loads(line)
    except ValueError:
        return []
    message = obj.get("message") if isinstance(obj, dict) and obj.get("type") == kind else None
    content = message.get("content") if isinstance(message, dict) else None
    return [b[key] for b in content if isinstance(b, dict) and b.get("type") == block_type
            and isinstance(b.get(key), str)] if isinstance(content, list) else []


def result_ids(line):
    """The tool_use ids a stream line carries results for: a `user` message's tool_results."""
    return _block_ids(line, "user", "tool_result", "tool_use_id")


def use_ids(line):
    """The tool_use ids a stream line starts: an `assistant` message's tool_uses."""
    return _block_ids(line, "assistant", "tool_use", "id")


class Stream:
    """The agent's stdout as it passes through: forwarded byte for byte, kept (spilled to a
    temp file past `spill_bytes` and bounded by `max_bytes`), and read line by line in O(N) time
    for the calls it starts and the results it reads back."""

    def __init__(self, fd, *, spill_bytes=None, max_bytes=None, max_line_bytes=None):
        self.fd, self.kept, self.open, self.eof = fd, bytearray(), True, False
        self._spill = None
        self.captured = 0
        self.truncated = False
        self.spill_bytes = SPILL_BYTES if spill_bytes is None else spill_bytes
        self.max_bytes = MAX_CAPTURE_BYTES if max_bytes is None else max_bytes
        self.max_line_bytes = MAX_LINE_BYTES if max_line_bytes is None else max_line_bytes
        self._partial_chunks = []
        self._partial_bytes = 0
        self._partial_oversized = False
        self.started = []
        self._started_set = set()

    def _keep(self, chunk):
        if self.truncated or not chunk:
            return
        if self.captured + len(chunk) > self.max_bytes:
            self.truncated = True
            return
        if self._spill is None and len(self.kept) + len(chunk) > self.spill_bytes:
            self._spill = tempfile.TemporaryFile(mode="w+b", prefix="of-traj-stream-")
            if self.kept:
                self._spill.write(self.kept)
                self.kept.clear()
        if self._spill is not None:
            self._spill.write(chunk)
        else:
            self.kept += chunk
        self.captured += len(chunk)

    def read_kept(self):
        """Return all captured stream bytes, reading back from the spill file when spilled."""
        if self._spill is not None:
            self._spill.flush()
            self._spill.seek(0)
            return self._spill.read()
        return bytes(self.kept)

    def close(self):
        if self._spill is not None:
            self._spill.close()
            self._spill = None

    def take(self, chunk):
        """Forward and keep `chunk`; the tool_use ids whose results its complete lines carry."""
        self._keep(chunk)
        self.open = _forward(sys.stdout.fileno(), chunk, self.open)
        if b"\n" not in chunk:
            if not self._partial_oversized:
                self._partial_bytes += len(chunk)
                if self._partial_bytes > self.max_line_bytes:
                    self._partial_chunks.clear()
                    self._partial_oversized = True
                else:
                    self._partial_chunks.append(chunk)
            return []
        first, *middle, tail = chunk.split(b"\n")
        lines = []
        if self._partial_oversized:
            self._partial_oversized = False
            self._partial_bytes = 0
        elif self._partial_chunks:
            if self._partial_bytes + len(first) <= self.max_line_bytes:
                self._partial_chunks.append(first)
                lines.append(b"".join(self._partial_chunks))
            self._partial_chunks.clear()
            self._partial_bytes = 0
        elif len(first) <= self.max_line_bytes:
            lines.append(first)
        for mid in middle:
            if len(mid) <= self.max_line_bytes:
                lines.append(mid)
        if tail:
            if len(tail) > self.max_line_bytes:
                self._partial_oversized = True
                self._partial_bytes = len(tail)
            else:
                self._partial_chunks.append(tail)
                self._partial_bytes = len(tail)
        return self.lines(lines)

    def lines(self, lines):
        results = []
        for line in lines:
            for uid in use_ids(line):
                if uid not in self._started_set:
                    self._started_set.add(uid)
                    self.started.append(uid)
            results += result_ids(line)
        return results

    def read(self):
        chunk = os.read(self.fd, 65536)
        self.eof = not chunk
        return self.take(chunk) if chunk else []

    def drain(self):
        """Everything already in the pipe, without waiting: a call whose tool_use was printed
        before a snapshot finished may have run before it."""
        results = []
        while not self.eof and select.select([self.fd], [], [], 0)[0]:
            results += self.read()
        return results

    def finish(self):
        if self._partial_oversized:
            self._partial_oversized = False
            self._partial_bytes = 0
            return []
        if not self._partial_chunks:
            return []
        last = b"".join(self._partial_chunks)
        self._partial_chunks.clear()
        self._partial_bytes = 0
        return self.lines([last])


def write_recording(dest, events):
    tmp = Path(f"{dest}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, dest)


def main(argv=None):
    flag, agent = parse_args(sys.argv[1:] if argv is None else argv)
    if not agent:
        print("trajectory_harness: usage: trajectory_harness.py [--trajectory-out PATH] [--] "
              "<agent command...>", file=sys.stderr)
        return EXIT_USAGE
    dest = destination(os.environ, flag)
    if dest is None:
        print("trajectory_harness: refusing to start: no recording destination (set ABLATION_OUT "
              "or pass --trajectory-out)", file=sys.stderr)
        return EXIT_USAGE
    dest = dest.resolve()
    refused = Path(f"{dest}.refused")
    dest.unlink(missing_ok=True)  # a stale recording must never be graded as this run's
    refused.unlink(missing_ok=True)
    workspace = Path.cwd()
    gnupghome = Path(tempfile.mkdtemp(prefix="of-harness-gnupg-"))
    try:
        env = isolated_env(os.environ, gnupghome)
        try:
            base = prepare_workspace(workspace, env)
        except (OSError, RuntimeError, subprocess.SubprocessError) as err:
            print(f"trajectory_harness: cannot prepare the workspace: {err}", file=sys.stderr)
            return EXIT_USAGE
        try:
            proc = subprocess.Popen(agent, stdout=subprocess.PIPE, env=env)
        except OSError as err:
            print(f"trajectory_harness: cannot start the agent: {err}", file=sys.stderr)
            return 127
        previous = {sig: signal.signal(sig, lambda signum, _frame: proc.send_signal(signum))
                    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
        out, history = Stream(proc.stdout.fileno()), []

        def snapshot(results):
            # Once results stream past, the workspace's history shows what those calls (or any
            # call already started) committed. What the pipe already holds is read first, so a
            # call that started before the snapshot finished is counted as started.
            while results:
                commits = commits_after(workspace, env, base)
                later = out.drain()
                history.append({"results": results, "started": list(out.started),
                                "commits": commits})
                results = later
        try:
            try:
                while not out.eof:
                    snapshot(out.read())
                snapshot(out.finish())
                code = proc.wait()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            if any(snap["commits"] is None for snap in history):
                history = None  # a snapshot git could not take: attribute named commits only
            if out.truncated:
                msg = f"stream exceeded capture limit ({out.max_bytes} bytes)"
                refused.write_text(f"{msg}\n", encoding="utf-8")
                print(f"trajectory_harness: recording refused: {msg}", file=sys.stderr)
            else:
                engine = _engine()
                try:
                    events = engine.record_stream(out.read_kept().decode("utf-8", "replace"), workspace,
                                                  base, history=history)
                    write_recording(dest, events)
                except engine.RecordingRefused as err:
                    refused.write_text(f"{err}\n", encoding="utf-8")
                    print(f"trajectory_harness: recording refused: {err}", file=sys.stderr)
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as err:
                    print(f"trajectory_harness: no recording written: {err}", file=sys.stderr)
        finally:
            out.close()
        return code if code >= 0 else 128 - code
    finally:
        shutil.rmtree(gnupghome, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
